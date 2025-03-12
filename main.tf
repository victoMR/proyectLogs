provider "google" {
  project = "mi-proyecto-k8s-453300"  # Tu ID de proyecto
  region  = "us-central1"             # Cambia a la región que prefieras
  credentials = file("credentials.json")  # Ruta a tu archivo de credenciales
}

resource "google_compute_address" "static_ip" {
  name = "mongodb-static-ip"
  region = "us-central1"  # Debe coincidir con la región de la instancia
}

resource "google_compute_instance" "mongodb_instance" {
  name         = "mongodb-instance"
  machine_type = "e2-micro"  # Tipo de máquina gratuita elegible
  zone         = "us-central1-a"  # Zona dentro de la región

  tags = ["mongodb"]

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2004-lts"  # Imagen de Ubuntu 20.04 LTS
    }
  }

  network_interface {
    network = "default"  # Usa la red predeterminada

    access_config {
      nat_ip = google_compute_address.static_ip.address
    }
  }

  # Script para instalar MongoDB
  metadata_startup_script = <<-EOF
                            #!/bin/bash
                            sudo apt-get update
                            sudo apt-get install -y mongodb
                            sudo systemctl start mongodb
                            sudo systemctl enable mongodb
                            EOF
}

output "mongodb_instance_public_ip" {
  value = google_compute_address.static_ip.address
}
