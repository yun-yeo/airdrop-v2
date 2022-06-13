use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cw_storage_plus::{Item, Map};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    pub admin: String,
    pub denom: String,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const LATEST_STAGE: Item<u8> = Item::new("latest_stage");

pub const MERKLE_ROOT: Map<&[u8], String> = Map::new("merkle_root");
pub const CLAIM_INDEX: Map<(&[u8], &[u8]), bool> = Map::new("claim_index");
