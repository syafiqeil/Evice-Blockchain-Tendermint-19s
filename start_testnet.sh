#!/bin/bash

# ==============================================================================
# SKRIP PENYIAPAN UNTUK TESTNET BLOCKCHAIN (MODE MANUAL DEBUG) - VERSI 6 NODE
# ==============================================================================

# Hentikan skrip jika ada perintah yang gagal
set -e

echo "===== FASE 1: PEMBERSIHAN DAN KOMPILASI ====="
# Hapus semua sisa pengujian sebelumnya untuk memastikan awal yang bersih
rm -rf ./permanent_testnet ./keystores ./database ./bootstrap_db *.pem *.crt *.key *.csr *.srl *.txt *.log san.cnf
echo "Lingkungan lama dibersihkan."

# Kompilasi ulang semua target yang dibutuhkan
echo "Mengompilasi proyek (pastikan NUM_VALIDATORS=6 di main.rs)..."
RUST_LOG=info,evice_blockchain=debug ROCKSDB_LIB_DIR=/usr/lib CXX=clang++ cargo build
echo "Proyek berhasil dikompilasi."

echo ""
echo "===== FASE 2: PEMBUATAN ASET KRIPTOGRAFI PERMANEN ====="

# 1. Buat file konfigurasi sertifikat (san.cnf)
cat <<EOF > san.cnf
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = localhost
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# 2. Buat CA, kunci server, dan sertifikat server
openssl genrsa -out ca.key 4096 &>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.pem -subj "/CN=MyTestCA" &>/dev/null
openssl req -new -nodes -newkey rsa:4096 -keyout server.key -out server.csr -config san.cnf &>/dev/null
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.crt -days 3650 -sha256 -extfile san.cnf -extensions v3_req &>/dev/null
mv server.crt cert.pem
mv server.key key.pem
echo "Sertifikat TLS permanen berhasil dibuat."

# 3. Buat direktori untuk testnet
mkdir -p ./permanent_testnet/node1 ./permanent_testnet/node2 ./permanent_testnet/node3 ./permanent_testnet/node4 ./permanent_testnet/node5 ./permanent_testnet/node6
echo "Struktur direktori testnet dibuat."

# 4. Jalankan bootstrap dan simpan "akta kelahiran" jaringan
target/debug/evice_blockchain --bootstrap > ./permanent_testnet/validator_keys.txt
echo "Genesis state berhasil di-bootstrap untuk 6 validator. Kunci disimpan di validator_keys.txt"

# 5. Salin genesis.json ke setiap direktori node
for i in {1..6}
do
    cp genesis.json ./permanent_testnet/node$i/
done

# 6. Buat dan tempatkan keystore untuk setiap validator
echo "Membuat keystore untuk para validator..."
for i in {1..6}
do
    PUB_KEY=$(grep -A 4 -e "--- Validator $i ---" ./permanent_testnet/validator_keys.txt | grep "Alamat (Sign PubKey)" | awk '{print $4}' | sed 's/0x//')
    PRIV_KEY=$(grep -A 4 -e "--- Validator $i ---" ./permanent_testnet/validator_keys.txt | grep "Signing Private Key" | awk '{print $4}' | sed 's/0x//')

    target/debug/create_keystore --import-public-key "$PUB_KEY" --import-private-key "$PRIV_KEY" --password "1234" &>/dev/null

    mkdir -p ./permanent_testnet/node$i/keystores
    mv ./keystores/UTC--* ./permanent_testnet/node$i/keystores/
done
echo "Semua 6 keystore berhasil dibuat."

echo ""
echo "✅ PENYIAPAN SELESAI! ✅"
echo ""
echo "=============================================================================="
echo "                PANDUAN MENJALANKAN TESTNET LOKAL (6 NODE)                    "
echo "=============================================================================="

# Ekstrak semua informasi yang diperlukan untuk ditampilkan kepada pengguna
LOG_LEVEL="info,evice_blockchain=debug"
L1_RPC_URL="https://127.0.0.1:8080"

# Info Validator 1
V1_VRF_PRIV_KEY=$(grep -A 4 -e "--- Validator 1 ---" ./permanent_testnet/validator_keys.txt | grep "VRF Secret Key" | awk '{print $4}' | sed 's/0x//')
KEYSTORE_1=$(find ./permanent_testnet/node1/keystores -type f)

# Info Validator 2
V2_VRF_PRIV_KEY=$(grep -A 4 -e "--- Validator 2 ---" ./permanent_testnet/validator_keys.txt | grep "VRF Secret Key" | awk '{print $4}' | sed 's/0x//')
KEYSTORE_2=$(find ./permanent_testnet/node2/keystores -type f)
V2_ADDR_HASH=$(basename "$KEYSTORE_2" | awk -F'--' '{print $3}')

# Info Validator 3
V3_VRF_PRIV_KEY=$(grep -A 4 -e "--- Validator 3 ---" ./permanent_testnet/validator_keys.txt | grep "VRF Secret Key" | awk '{print $4}' | sed 's/0x//')
KEYSTORE_3=$(find ./permanent_testnet/node3/keystores -type f)

# Info Validator 4
V4_VRF_PRIV_KEY=$(grep -A 4 -e "--- Validator 4 ---" ./permanent_testnet/validator_keys.txt | grep "VRF Secret Key" | awk '{print $4}' | sed 's/0x//')
KEYSTORE_4=$(find ./permanent_testnet/node4/keystores -type f)

# Info Validator 5
V5_VRF_PRIV_KEY=$(grep -A 4 -e "--- Validator 5 ---" ./permanent_testnet/validator_keys.txt | grep "VRF Secret Key" | awk '{print $4}' | sed 's/0x//')
KEYSTORE_5=$(find ./permanent_testnet/node5/keystores -type f)

# Info Validator 6 (BARU)
V6_VRF_PRIV_KEY=$(grep -A 4 -e "--- Validator 6 ---" ./permanent_testnet/validator_keys.txt | grep "VRF Secret Key" | awk '{print $4}' | sed 's/0x//')
KEYSTORE_6=$(find ./permanent_testnet/node6/keystores -type f)


# Tampilkan perintah untuk menjalankan node
echo ""
echo ""
echo "------------------------------ TERMINAL 1 (Node Bootstrap) ------------------------------"
echo "RUST_LOG=$LOG_LEVEL target/debug/evice_blockchain \\"
echo "    --db-path ./permanent_testnet/node1/database \\"
echo "    --is-authority \\"
echo "    --keystore-path '$KEYSTORE_1' \\"
echo "    --vrf-private-key '$V1_VRF_PRIV_KEY' \\"
echo "    --password '1234'"
echo ""

echo ""
echo ""
echo "------------------------------ TERMINAL 2 ------------------------------"
echo "RUST_LOG=$LOG_LEVEL target/debug/evice_blockchain \\"
echo "    --db-path ./permanent_testnet/node2/database \\"
echo "    --rpc-port 8081 \\"
echo "    --p2p-port 50001 \\"
echo "    --is-authority \\"
echo "    --keystore-path '$KEYSTORE_2' \\"
echo "    --vrf-private-key '$V2_VRF_PRIV_KEY' \\"
echo "    --bootstrap-node \"/ip4/127.0.0.1/tcp/50000/p2p/\" \\"
echo "    --password '1234'"
echo ""

echo ""
echo ""
echo "------------------------------ TERMINAL 3 ------------------------------"
echo "RUST_LOG=$LOG_LEVEL target/debug/evice_blockchain \\"
echo "    --db-path ./permanent_testnet/node3/database \\"
echo "    --rpc-port 8082 \\"
echo "    --p2p-port 50002 \\"
echo "    --is-authority \\"
echo "    --keystore-path '$KEYSTORE_3' \\"
echo "    --vrf-private-key '$V3_VRF_PRIV_KEY' \\"
echo "    --bootstrap-node \"/ip4/127.0.0.1/tcp/50000/p2p/\" \\"
echo "    --password '1234'"
echo ""

echo ""
echo ""
echo "------------------------------ TERMINAL 4 ------------------------------"
echo "RUST_LOG=$LOG_LEVEL target/debug/evice_blockchain \\"
echo "    --db-path ./permanent_testnet/node4/database \\"
echo "    --rpc-port 8083 \\"
echo "    --p2p-port 50003 \\"
echo "    --is-authority \\"
echo "    --keystore-path '$KEYSTORE_4' \\"
echo "    --vrf-private-key '$V4_VRF_PRIV_KEY' \\"
echo "    --bootstrap-node \"/ip4/127.0.0.1/tcp/50000/p2p/\" \\"
echo "    --password '1234'"
echo ""

echo ""
echo ""
echo "------------------------------ TERMINAL 5 ------------------------------"
echo "RUST_LOG=$LOG_LEVEL target/debug/evice_blockchain \\"
echo "    --db-path ./permanent_testnet/node5/database \\"
echo "    --rpc-port 8084 \\"
echo "    --p2p-port 50004 \\"
echo "    --is-authority \\"
echo "    --keystore-path '$KEYSTORE_5' \\"
echo "    --vrf-private-key '$V5_VRF_PRIV_KEY' \\"
echo "    --bootstrap-node \"/ip4/127.0.0.1/tcp/50000/p2p/\" \\"
echo "    --password '1234'"
echo ""

echo ""
echo ""
echo "------------------------------ TERMINAL 6 ------------------------------"
echo "RUST_LOG=$LOG_LEVEL target/debug/evice_blockchain \\"
echo "    --db-path ./permanent_testnet/node6/database \\"
echo "    --rpc-port 8085 \\"
echo "    --p2p-port 50005 \\"
echo "    --is-authority \\"
echo "    --keystore-path '$KEYSTORE_6' \\"
echo "    --vrf-private-key '$V6_VRF_PRIV_KEY' \\"
echo "    --bootstrap-node \"/ip4/127.0.0.1/tcp/50000/p2p/\" \\"
echo "    --password '1234'"
echo ""


echo "=============================================================================="
echo "              PERINTAH PENGUJIAN FUNGSIONALITAS INTI                          "
echo "=============================================================================="
echo ""
echo "--- 1. TRANSFER ---"
echo "# Transfer 100 token dari Validator 1 ke Validator 2:"
echo "echo \"1234\" | target/debug/create_tx --l1-rpc-url $L1_RPC_URL transfer --keystore-path '$KEYSTORE_1' --recipient '$V2_ADDR_HASH' --amount 100 --nonce 0"
echo ""
echo "--- 2. STAKING ---"
echo "# Validator 2 melakukan staking tambahan sebesar 5000 token:"
echo "echo \"1234\" | target/debug/create_tx --l1-rpc-url $L1_RPC_URL stake --keystore-path '$KEYSTORE_2' --amount 5000 --nonce 0"
echo ""
echo "--- 3. GOVERNANCE (MEMBUAT PROPOSAL) ---"
echo "# Validator 1 mengajukan proposal baru:"
echo "echo \"1234\" | target/debug/create_tx --l1-rpc-url $L1_RPC_URL submit-proposal --keystore-path '$KEYSTORE_1' --nonce 1 --title \"(Roadmap) Pengembangan Q4 2025\" --description \"Menerapkan Fungsionalitas Penuh untuk Smart Contract\""
echo ""
echo "--- 4. GOVERNANCE (MEMBERIKAN SUARA) ---"
echo "# Validator 2 memberikan suara 'Ya' pada proposal dengan ID 0:"
echo "echo \"1234\" | target/debug/create_tx --l1-rpc-url $L1_RPC_URL cast-vote --keystore-path '$KEYSTORE_2' --nonce 1 --proposal-id 0 --vote-yes"
echo ""
echo "--- 5. BRIDGE DEPOSIT (L1 -> L2) ---"
echo "# Validator 3 melakukan deposit 2500 token ke bridge contract di L1:"
echo "echo \"1234\" | target/debug/create_tx --l1-rpc-url $L1_RPC_URL deposit --keystore-path '$KEYSTORE_3' --amount 2500 --nonce 0"
echo "=============================================================================="
echo ""