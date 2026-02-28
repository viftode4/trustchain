//! gRPC service implementation for the TrustChain protocol.

use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

use trustchain_core::{BlockStore, HalfBlock, TrustChainProtocol};

use crate::discovery::PeerDiscovery;
use crate::proto;

/// Convert a core HalfBlock to its protobuf representation.
pub fn block_to_proto(block: &HalfBlock) -> proto::HalfBlockProto {
    proto::HalfBlockProto {
        public_key: block.public_key.clone(),
        sequence_number: block.sequence_number,
        link_public_key: block.link_public_key.clone(),
        link_sequence_number: block.link_sequence_number,
        previous_hash: block.previous_hash.clone(),
        signature: block.signature.clone(),
        block_type: block.block_type.clone(),
        transaction: serde_json::to_string(&block.transaction).unwrap_or_default(),
        block_hash: block.block_hash.clone(),
        timestamp: block.timestamp,
    }
}

/// Convert a protobuf HalfBlock to the core type.
pub fn proto_to_block(proto: &proto::HalfBlockProto) -> Result<HalfBlock, Status> {
    let transaction: serde_json::Value =
        serde_json::from_str(&proto.transaction).map_err(|e| {
            Status::invalid_argument(format!("invalid transaction JSON: {e}"))
        })?;

    Ok(HalfBlock {
        public_key: proto.public_key.clone(),
        sequence_number: proto.sequence_number,
        link_public_key: proto.link_public_key.clone(),
        link_sequence_number: proto.link_sequence_number,
        previous_hash: proto.previous_hash.clone(),
        signature: proto.signature.clone(),
        block_type: proto.block_type.clone(),
        transaction,
        block_hash: proto.block_hash.clone(),
        timestamp: proto.timestamp,
    })
}

/// gRPC service implementation, generic over any BlockStore.
pub struct TrustChainGrpcService<S: BlockStore + 'static> {
    protocol: Arc<Mutex<TrustChainProtocol<S>>>,
    discovery: Arc<PeerDiscovery>,
}

impl<S: BlockStore + 'static> TrustChainGrpcService<S> {
    pub fn new(
        protocol: Arc<Mutex<TrustChainProtocol<S>>>,
        discovery: Arc<PeerDiscovery>,
    ) -> Self {
        Self {
            protocol,
            discovery,
        }
    }
}

#[tonic::async_trait]
impl<S: BlockStore + 'static> proto::trust_chain_service_server::TrustChainService
    for TrustChainGrpcService<S>
{
    async fn propose(
        &self,
        request: Request<proto::ProposalRequest>,
    ) -> Result<Response<proto::AgreementResponse>, Status> {
        let req = request.into_inner();
        let proposal_proto = req
            .proposal
            .ok_or_else(|| Status::invalid_argument("missing proposal"))?;

        let proposal = proto_to_block(&proposal_proto)?;

        let mut proto_lock = self.protocol.lock().await;

        // Receive the proposal.
        if let Err(e) = proto_lock.receive_proposal(&proposal) {
            return Ok(Response::new(proto::AgreementResponse {
                agreement: None,
                accepted: false,
                reason: e.to_string(),
            }));
        }

        // Create agreement.
        match proto_lock.create_agreement(&proposal, None) {
            Ok(agreement) => Ok(Response::new(proto::AgreementResponse {
                agreement: Some(block_to_proto(&agreement)),
                accepted: true,
                reason: String::new(),
            })),
            Err(e) => Ok(Response::new(proto::AgreementResponse {
                agreement: None,
                accepted: false,
                reason: e.to_string(),
            })),
        }
    }

    async fn crawl(
        &self,
        request: Request<proto::CrawlRequest>,
    ) -> Result<Response<proto::CrawlResponse>, Status> {
        let req = request.into_inner();
        let proto_lock = self.protocol.lock().await;

        let blocks = proto_lock
            .store()
            .crawl(&req.public_key, req.start_seq)
            .map_err(|e| Status::internal(e.to_string()))?;

        let proto_blocks: Vec<proto::HalfBlockProto> =
            blocks.iter().map(block_to_proto).collect();

        Ok(Response::new(proto::CrawlResponse {
            blocks: proto_blocks,
        }))
    }

    async fn get_status(
        &self,
        _request: Request<proto::StatusRequest>,
    ) -> Result<Response<proto::StatusResponse>, Status> {
        let proto_lock = self.protocol.lock().await;
        let pubkey = proto_lock.pubkey();

        let latest_seq = proto_lock
            .store()
            .get_latest_seq(&pubkey)
            .map_err(|e| Status::internal(e.to_string()))?;
        let block_count = proto_lock
            .store()
            .get_block_count()
            .map_err(|e| Status::internal(e.to_string()))?;

        let peers = self.discovery.get_peers().await;
        let known_peers: Vec<proto::PeerInfo> = peers
            .iter()
            .map(|p| proto::PeerInfo {
                public_key: p.pubkey.clone(),
                address: p.address.clone(),
                latest_seq: p.latest_seq,
                last_seen: {
                    let now = crate::discovery::now_unix_ms();
                    (now.saturating_sub(p.last_seen_unix_ms) as f64) / 1000.0
                },
            })
            .collect();

        Ok(Response::new(proto::StatusResponse {
            public_key: pubkey,
            latest_seq,
            block_count: block_count as u64,
            known_peers,
        }))
    }

    async fn discover_peers(
        &self,
        request: Request<proto::DiscoveryRequest>,
    ) -> Result<Response<proto::DiscoveryResponse>, Status> {
        let req = request.into_inner();

        // Merge incoming peers.
        for peer in &req.known_peers {
            self.discovery
                .add_peer(
                    peer.public_key.clone(),
                    peer.address.clone(),
                    peer.latest_seq,
                )
                .await;
        }

        // Return our known peers.
        let our_peers = self.discovery.get_gossip_peers(20).await;
        let peers: Vec<proto::PeerInfo> = our_peers
            .iter()
            .map(|p| proto::PeerInfo {
                public_key: p.pubkey.clone(),
                address: p.address.clone(),
                latest_seq: p.latest_seq,
                last_seen: {
                    let now = crate::discovery::now_unix_ms();
                    (now.saturating_sub(p.last_seen_unix_ms) as f64) / 1000.0
                },
            })
            .collect();

        Ok(Response::new(proto::DiscoveryResponse { peers }))
    }
}

/// Start the gRPC server.
pub async fn start_grpc_server<S: BlockStore + 'static>(
    addr: std::net::SocketAddr,
    protocol: Arc<Mutex<TrustChainProtocol<S>>>,
    discovery: Arc<PeerDiscovery>,
) -> Result<(), Box<dyn std::error::Error>> {
    let service = TrustChainGrpcService::new(protocol, discovery);

    log::info!("gRPC server listening on {addr}");

    tonic::transport::Server::builder()
        .add_service(
            proto::trust_chain_service_server::TrustChainServiceServer::new(service),
        )
        .serve(addr)
        .await?;

    Ok(())
}
