terraform {
    required_providers {
        google = {
            source ="hashicorp/google"
            version = "~> 5.0"
        }
    }   
}

provider "google" {
    project = "ebpf-analyzer"
    region =  "asia-northeast1"
}

resource "google_container_cluster" "primary" {
    name = "ebpf-analyzer-cluster"
    location = "asia-northeast1"

    remove_default_node_pool = true
    initial_node_count = 1   
}

resource "google_container_node_pool" "parimary_nodes" {
    name = "ebpf-analyzer-node-pool"
    location = "asia-northeast1"
    cluster = google_container_cluster.primary.name

    node_count = 1

    node_config {
        preemptible = true
        machine_type = "e2-medium"
        disk_size_gb = 20

    }
}