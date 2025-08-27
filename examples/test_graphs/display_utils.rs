use virustotal_rs::comments::Comment;
use virustotal_rs::graphs::{Graph, GraphAttributes, GraphOwner, GraphRelationshipDescriptor};
use virustotal_rs::objects::CollectionMeta;

pub fn display_pagination_info(meta: &Option<CollectionMeta>) {
    if let Some(meta) = meta {
        if let Some(cursor) = &meta.cursor {
            println!(
                "   - Cursor for pagination: {}",
                &cursor[..20.min(cursor.len())]
            );
        }
    }
}

/// Display individual graph information
pub fn display_single_graph_info(graph: &Graph) {
    println!("   - Graph ID: {}", graph.object.id);
    display_graph_basic_info(&graph.object.attributes);
    display_graph_metrics(&graph.object.attributes);
    display_graph_owner(&graph.object.attributes);
}

/// Display list of graphs
pub fn display_graph_list(graphs: &[Graph]) {
    for graph in graphs.iter().take(5) {
        display_single_graph_info(graph);
    }
}

pub fn display_graph_basic_info(attributes: &GraphAttributes) {
    if let Some(name) = &attributes.name {
        print!("     Name: {}", name);
    }
    if let Some(visibility) = &attributes.visibility {
        print!(" [{}]", visibility);
    }
    println!();
}

pub fn display_graph_metrics(attributes: &GraphAttributes) {
    if let Some(nodes) = &attributes.nodes_count {
        print!("     Nodes: {}", nodes);
    }
    if let Some(edges) = &attributes.edges_count {
        print!(", Edges: {}", edges);
    }
    println!();
}

pub fn display_graph_owner(attributes: &GraphAttributes) {
    if let Some(owner) = &attributes.owner {
        println!("     Owner: {}", owner);
    }
}

pub fn display_created_graph_info(graph: &Graph) {
    println!("   - ID: {}", graph.object.id);
    if let Some(name) = &graph.object.attributes.name {
        println!("   - Name: {}", name);
    }
    if let Some(creation_date) = &graph.object.attributes.creation_date {
        println!("   - Created: {}", creation_date);
    }
}

pub fn display_graph_details(attributes: &GraphAttributes) {
    if let Some(name) = &attributes.name {
        println!("   - Name: {}", name);
    }
    if let Some(description) = &attributes.description {
        println!("   - Description: {}", description);
    }
    if let Some(graph_type) = &attributes.graph_type {
        println!("   - Type: {}", graph_type);
    }
    if let Some(visibility) = &attributes.visibility {
        println!("   - Visibility: {}", visibility);
    }
    if let Some(tags) = &attributes.tags {
        if !tags.is_empty() {
            println!("   - Tags: {}", tags.join(", "));
        }
    }
}

pub fn display_updated_graph_info(attributes: &GraphAttributes) {
    if let Some(name) = &attributes.name {
        println!("   - New name: {}", name);
    }
    if let Some(visibility) = &attributes.visibility {
        println!("   - New visibility: {}", visibility);
    }
    if let Some(modification_date) = &attributes.modification_date {
        println!("   - Modified: {}", modification_date);
    }
}

pub fn display_comment_list(comments: &[Comment]) {
    for comment in comments.iter().take(5) {
        println!("\n   Comment ID: {}", comment.object.id);
        println!("   - Text: {}", comment.object.attributes.text);

        if let Some(date) = &comment.object.attributes.date {
            println!("   - Date: {}", date);
        }

        if let Some(votes) = &comment.object.attributes.votes {
            println!("   - Votes: +{} -{}", votes.positive, votes.negative);
        }
    }
}

pub fn display_search_results(graphs: &[Graph]) {
    for graph in graphs.iter().take(3) {
        println!("   - Graph ID: {}", graph.object.id);
        if let Some(name) = &graph.object.attributes.name {
            println!("     Name: {}", name);
        }
    }
}

pub fn display_paginated_graphs(batch: &[Graph]) {
    for graph in batch.iter().take(3) {
        if let Some(name) = &graph.object.attributes.name {
            println!("   - {}", name);
        }
    }
}

pub fn display_paginated_comments(batch: &[Comment]) {
    for comment in batch.iter().take(3) {
        let text = &comment.object.attributes.text;
        println!("   - {}", &text[..50.min(text.len())]);
    }
}

pub fn display_viewer_descriptors(descriptors: &[GraphRelationshipDescriptor]) {
    for descriptor in descriptors.iter().take(3) {
        println!("   - {} (ID: {})", descriptor.object_type, descriptor.id);
    }
}

pub fn display_owner_info(owner: &GraphOwner) {
    println!("   - User ID: {}", owner.object.id);

    if let Some(first_name) = &owner.object.attributes.first_name {
        if let Some(last_name) = &owner.object.attributes.last_name {
            println!("   - Name: {} {}", first_name, last_name);
        }
    }

    if let Some(status) = &owner.object.attributes.status {
        println!("   - Status: {}", status);
    }

    if let Some(reputation) = &owner.object.attributes.reputation {
        println!("   - Reputation: {}", reputation);
    }
}

pub fn display_editor_list(editors: &[GraphOwner]) {
    for editor in editors.iter().take(3) {
        println!("   - Editor: {}", editor.object.id);
    }
}

pub fn display_relationship_descriptors(descriptors: &[GraphRelationshipDescriptor]) {
    for descriptor in descriptors.iter().take(3) {
        println!("   - {} (ID: {})", descriptor.object_type, descriptor.id);
        if let Some(context) = &descriptor.context_attributes {
            println!("     Context: {:?}", context);
        }
    }
}
