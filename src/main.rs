extern crate pnet;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::env;
use std::time::Instant;

const TIMEOUT_THRESHOLD: u64 = 5;

fn main() {
    let interface_name = match env::args().nth(1) {
        Some(name) => name,
        None => {
            println!("Por favor, especifique o nome da interface de rede como argumento de linha de comando.");
            return;
        }
    };

    let interface_names_match =
        |iface: &NetworkInterface| iface.name == interface_name;

    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
                              .filter(interface_names_match)
                              .next()
                              .unwrap_or_else(|| {
                                  panic!("Nenhuma interface de rede encontrada com o nome fornecido.");
                              });

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return,
        Err(e) => panic!("Ocorreu um erro ao criar o canal de datalink: {}", e)
    };

    let mut devices_map: HashMap<String, Instant> = HashMap::new();

    loop {
        println!("Selecione uma opção:");
        println!("1. Visualizar todos os pacotes");
        println!("2. Visualizar dispositivos conectados em tempo real");
        println!("3. Analisar atividades de rede em tempo real");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).expect("Falha ao ler entrada");

        match input.trim() {
            "1" => {
                while let Ok(packet) = rx.next() {
                    let ethernet_packet = EthernetPacket::new(packet).unwrap();
                    println!("{:?}", ethernet_packet);
                }
            }
            "2" => {
                while let Ok(packet) = rx.next() {
                    let ethernet_packet = EthernetPacket::new(packet).unwrap();
                    let source_mac = format!("{:?}", ethernet_packet.get_source());

                    if !devices_map.contains_key(&source_mac) {
                        devices_map.insert(source_mac.clone(), Instant::now());
                        println!("Novo dispositivo detectado - Endereço MAC: {}", source_mac);
                    } else {
                        devices_map.insert(source_mac.clone(), Instant::now());
                    }

                    let now = Instant::now();
                    let mut devices_to_remove = Vec::new();
                    for (mac, timestamp) in &devices_map {
                        let elapsed = now.duration_since(*timestamp).as_secs();
                        if elapsed >= TIMEOUT_THRESHOLD {
                            devices_to_remove.push(mac.clone());
                        }
                    }
                    for mac in devices_to_remove {
                        devices_map.remove(&mac);
                        println!("Dispositivo saiu da rede - Endereço MAC: {}", mac);
                    }
                }
            }
            "3" => {
                while let Ok(packet) = rx.next() {
                    let ethernet_packet = EthernetPacket::new(packet).unwrap();
                    if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                                if tcp_packet.get_flags() & 0x02 != 0 && tcp_packet.get_flags() & 0x10 == 0 {
                                    println!("Possível escaneamento de portas TCP de {} para {}: {:?}", ipv4_packet.get_source(), ipv4_packet.get_destination(), tcp_packet);
                                }
                            } else if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                                if udp_packet.get_length() == 0 {
                                    println!("Pacote UDP vazio de {} para {}", ipv4_packet.get_source(), ipv4_packet.get_destination());
                                }
                            }
                        }
                    }
                }
            }
            _ => println!("Opção inválida!"),
        }
    }
}
