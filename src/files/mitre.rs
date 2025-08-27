//! MITRE ATT&CK framework structures

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTrees {
    pub data: HashMap<String, SandboxMitreData>,
    pub links: Option<MitreLinks>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreLinks {
    #[serde(rename = "self")]
    pub self_link: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxMitreData {
    pub tactics: Vec<MitreTactic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTactic {
    pub id: String,
    pub name: String,
    pub description: String,
    pub link: String,
    pub techniques: Vec<MitreTechnique>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub description: String,
    pub link: String,
    pub signatures: Vec<MitreSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreSignature {
    pub severity: MitreSeverity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum MitreSeverity {
    High,
    Medium,
    Low,
    Info,
    Unknown,
}
