/*****************************************************************************
 OSSLMPCECDSA.h

 OpenSSL MPC ECDSA asymmetric algorithm implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLMPCECDSA_TEMPLATES_H
#define _SOFTHSM_V2_OSSLMPCECDSA_TEMPLATES_H

#include <iostream>
#include <openssl/rand.h>
#include <chrono>
#include <shared_mutex>
#include <uuid/uuid.h>
#include "cosigner/sign_algorithm.h"
#include "cosigner/cmp_setup_service.h"
#include "cosigner/cmp_ecdsa_online_signing_service.h"
#include "cosigner/cosigner_exception.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/mpc_globals.h"

#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */

const std::string separator = std::string("****************************************************************************");
#define COSIGNER_LOG(__id__, __mess__)            \
    std::cerr                                     \
        << colorized_outputs.at(__id__)           \
        << separator << std::endl                 \
        << "COSIGNER_" << __id__                  \
        << " \n\t\t " << __mess__  << std::endl

#define COSIGNER_RESET() std::cerr << RESET
static const std::map<size_t, std::string> colorized_outputs = {
    {1, MAGENTA},
    {2, YELLOW},
    {3, RED},
};

using namespace fireblocks::common::cosigner;

static elliptic_curve256_algebra_ctx_t* create_algebra(cosigner_sign_algorithm type)
{
    switch (type)
    {
        case ECDSA_SECP256K1: return elliptic_curve256_new_secp256k1_algebra();
        case ECDSA_SECP256R1: return elliptic_curve256_new_secp256r1_algebra();
        case ECDSA_STARK: return elliptic_curve256_new_stark_algebra();
        case EDDSA_ED25519: return NULL;
    }
    return NULL;
}

static const std::string TENANT_ID("test tenant");

class setup_persistency : public cmp_setup_service::setup_key_persistency
{
private:
    bool key_exist(const std::string& key_id) const override;
    void load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const override;
    const std::string get_tenantid_from_keyid(const std::string& key_id) const override;
    void load_key_metadata(const std::string& key_id, cmp_key_metadata& metadata, bool full_load) const override;
    void load_auxiliary_keys(const std::string& key_id, auxiliary_keys& aux) const override;
    void store_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, uint64_t ttl = 0) override;
    void store_key_metadata(const std::string& key_id, const cmp_key_metadata& metadata, bool allow_override) override;
    void store_auxiliary_keys(const std::string& key_id, const auxiliary_keys& aux) override;
    void store_keyid_tenant_id(const std::string& key_id, const std::string& tenant_id) override;
    void store_setup_data(const std::string& key_id, const setup_data& metadata) override;
    void load_setup_data(const std::string& key_id, setup_data& metadata) override;
    void store_setup_commitments(const std::string& key_id, const std::map<uint64_t, commitment>& commitments) override;
    void load_setup_commitments(const std::string& key_id, std::map<uint64_t, commitment>& commitments) override;
    void delete_temporary_key_data(const std::string& key_id, bool delete_key = false) override;

    struct key_info
    {
        cosigner_sign_algorithm algorithm;
        elliptic_curve256_scalar_t private_key;
        std::optional<cmp_key_metadata> metadata;
        auxiliary_keys aux_keys;
    };

    std::map<std::string, key_info> _keys;
    std::map<std::string, setup_data> _setup_data;
    std::map<std::string, std::map<uint64_t, commitment>> _commitments;
};

bool setup_persistency::key_exist(const std::string& key_id) const
{
    return _keys.find(key_id) != _keys.end();
}

void setup_persistency::load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const
{
    auto it = _keys.find(key_id);
    if (it == _keys.end())
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    memcpy(private_key, it->second.private_key, sizeof(elliptic_curve256_scalar_t));
    algorithm = it->second.algorithm;
}

const std::string setup_persistency::get_tenantid_from_keyid(const std::string&) const
{
    return TENANT_ID;
}

void setup_persistency::load_key_metadata(const std::string& key_id, cmp_key_metadata& metadata, bool) const
{
    auto it = _keys.find(key_id);
    if (it == _keys.end())
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    metadata = it->second.metadata.value();
}

void setup_persistency::load_auxiliary_keys(const std::string& key_id, auxiliary_keys& aux) const
{
    auto it = _keys.find(key_id);
    if (it == _keys.end())
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    aux = it->second.aux_keys;
}

void setup_persistency::store_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, uint64_t)
{
    auto& info = _keys[key_id];
    memcpy(info.private_key, private_key, sizeof(elliptic_curve256_scalar_t));
    info.algorithm = algorithm;
}

void setup_persistency::store_key_metadata(const std::string& key_id, const cmp_key_metadata& metadata, bool allow_override)
{
    auto& info = _keys[key_id];
    if (!allow_override && info.metadata)
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);

    info.metadata = metadata;
}

void setup_persistency::store_auxiliary_keys(const std::string& key_id, const auxiliary_keys& aux)
{
    auto& info = _keys[key_id];
    info.aux_keys = aux;
}

void setup_persistency::store_keyid_tenant_id(const std::string&, const std::string&) {}

void setup_persistency::store_setup_data(const std::string& key_id, const setup_data& metadata)
{
    _setup_data[key_id] = metadata;
}

void setup_persistency::load_setup_data(const std::string& key_id, setup_data& metadata)
{
    metadata = _setup_data[key_id];
}

void setup_persistency::store_setup_commitments(const std::string& key_id, const std::map<uint64_t, commitment>& commitments)
{
    if (_commitments.find(key_id) != _commitments.end())
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);

    _commitments[key_id] = commitments;
}

void setup_persistency::load_setup_commitments(const std::string& key_id, std::map<uint64_t, commitment>& commitments)
{
    commitments = _commitments[key_id];
}

void setup_persistency::delete_temporary_key_data(const std::string& key_id, bool delete_key)
{
    _setup_data.erase(key_id);
    _commitments.erase(key_id);
    if (delete_key)
        _keys.erase(key_id);
}

class platform : public platform_service
{
public:
    platform(uint64_t id) : _id(id) {}
private:
    void gen_random(size_t len, uint8_t* random_data) const
    {
        RAND_bytes(random_data, len);
    }

    uint64_t now_msec() const override { return std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()).time_since_epoch().count(); }

    const std::string get_current_tenantid() const {return TENANT_ID;}
    uint64_t get_id_from_keyid(const std::string&) const {return _id;}
    void derive_initial_share(const share_derivation_args&, cosigner_sign_algorithm, elliptic_curve256_scalar_t*) const {assert(0);}
    byte_vector_t encrypt_for_player(uint64_t, const byte_vector_t& data) const {return data;}
    byte_vector_t decrypt_message(const byte_vector_t& encrypted_data) const {return encrypted_data;}
    bool backup_key(const std::string&, cosigner_sign_algorithm, const elliptic_curve256_scalar_t&, const cmp_key_metadata&, const auxiliary_keys&) {return true;}
    void start_signing(const std::string&, const std::string&, const signing_data&, const std::string&, const std::set<std::string>&) {}
    void fill_signing_info_from_metadata(const std::string&, std::vector<uint32_t>&) const {assert(0);}
    bool is_client_id(uint64_t) const override {return false;}

    uint64_t _id;
};

typedef std::map<uint64_t, setup_persistency> players_setup_info;

struct setup_info
{
    setup_info(uint64_t id, setup_persistency& persistency) : platform_service(id), setup_service(platform_service, persistency) {}
    platform platform_service;
    cmp_setup_service setup_service;
};

/********************************************************
 *
 *             MPC-ECDSA Key GENERATION
 *
 ********************************************************/
static void create_secret(players_setup_info& players, cosigner_sign_algorithm type, const std::string& keyid, elliptic_curve256_point_t& pubkey)
{
    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> algebra(create_algebra(type), elliptic_curve256_algebra_ctx_free);
    const size_t PUBKEY_SIZE = algebra->point_size(algebra.get());
    memset(pubkey, 0, sizeof(elliptic_curve256_point_t));

    std::vector<uint64_t> players_ids;

    std::map<uint64_t, std::unique_ptr<setup_info>> services;
    for (auto i = players.begin(); i != players.end(); ++i)
    {
        services.emplace(i->first, std::make_unique<setup_info>(i->first, i->second));
        players_ids.push_back(i->first);
    }

    std::map<uint64_t, commitment> commitments;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        COSIGNER_LOG(i->first, "Creating commitment");
        commitment& commit = commitments[i->first];
        i->second->setup_service.generate_setup_commitments(keyid, TENANT_ID, type, players_ids, players_ids.size(), 0, {}, commit);
    }

    std::map<uint64_t, setup_decommitment> decommitments;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        COSIGNER_LOG(i->first, "Sending decommitment");
        setup_decommitment& decommitment = decommitments[i->first];
        i->second->setup_service.store_setup_commitments(keyid, commitments, decommitment);
    }
    commitments.clear();

    std::map<uint64_t, setup_zk_proofs> proofs;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        COSIGNER_LOG(i->first, "Computing Setup ZK Proofs");
        setup_zk_proofs& proof = proofs[i->first];
        i->second->setup_service.generate_setup_proofs(keyid, decommitments, proof);
    }
    decommitments.clear();

    std::map<uint64_t, std::map<uint64_t, byte_vector_t>> paillier_large_factor_proofs;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        COSIGNER_LOG(i->first, "Verifying Setup ZK Proofs");
        auto& proof = paillier_large_factor_proofs[i->first];
        i->second->setup_service.verify_setup_proofs(keyid, proofs, proof);
    }
    proofs.clear();

    bool first = true;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        COSIGNER_LOG(i->first, "Creating secret share");
        std::string public_key;
        cosigner_sign_algorithm algorithm;
        i->second->setup_service.create_secret(keyid, paillier_large_factor_proofs, public_key, algorithm);
        if (first)
        {
            first = false;
            memcpy(pubkey, public_key.data(), PUBKEY_SIZE);
        }
    }
    paillier_large_factor_proofs.clear();

    for (auto i = services.begin(); i != services.end(); ++i)
    {
        COSIGNER_LOG(i->first, "** END OF KEY GENERATION **");
    }
    COSIGNER_RESET();
}


/********************************************************
 *
 *             MPC-ECDSA SIGNATURE
 *
 ********************************************************/
using Clock = std::conditional<std::chrono::high_resolution_clock::is_steady, std::chrono::high_resolution_clock,
        std::chrono::steady_clock>::type;

class sign_platform : public platform_service
{
public:
    sign_platform(uint64_t id, bool positive_r) : _id(id), _positive_r(positive_r) {}
private:
    void gen_random(size_t len, uint8_t* random_data) const
    {
        RAND_bytes(random_data, len);
    }

    uint64_t now_msec() const override { return std::chrono::time_point_cast<std::chrono::milliseconds>(Clock::now()).time_since_epoch().count(); }

    const std::string get_current_tenantid() const {return TENANT_ID;}
    uint64_t get_id_from_keyid(const std::string&) const {return _id;}
    void derive_initial_share(const share_derivation_args&, cosigner_sign_algorithm, elliptic_curve256_scalar_t*) const {assert(0);}
    byte_vector_t encrypt_for_player(uint64_t, const byte_vector_t&) const {assert(0);}
    byte_vector_t decrypt_message(const byte_vector_t&) const {assert(0);}
    bool backup_key(const std::string&, cosigner_sign_algorithm, const elliptic_curve256_scalar_t&, const cmp_key_metadata&, const auxiliary_keys&) {return true;}
    void start_signing(const std::string&, const std::string&, const signing_data&, const std::string&, const std::set<std::string>&) {}
    void fill_signing_info_from_metadata(const std::string&, std::vector<uint32_t>&) const {}
    bool is_client_id(uint64_t) const override {return false;}

    const uint64_t _id;
    const bool _positive_r;
};

class online_signing_persistency : public cmp_ecdsa_online_signing_service::signing_persistency
{
    void store_cmp_signing_data(const std::string& txid, const cmp_signing_metadata& data) override
    {
        std::unique_lock lock(_mutex);
        if (_metadata.find(txid) != _metadata.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        _metadata[txid] = data;
    }

    void load_cmp_signing_data(const std::string& txid, cmp_signing_metadata& data) const override
    {
        std::shared_lock lock(_mutex);
        auto it = _metadata.find(txid);
        if (it == _metadata.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        data = it->second;
    }

    void update_cmp_signing_data(const std::string& txid, const cmp_signing_metadata& data) override
    {
        std::unique_lock lock(_mutex);
        auto it = _metadata.find(txid);
        if (it == _metadata.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        it->second = data;
    }

    void delete_signing_data(const std::string& txid) override
    {
        std::unique_lock lock(_mutex);
        _metadata.erase(txid);
    }

    mutable std::shared_mutex _mutex;
    std::map<std::string, cmp_signing_metadata> _metadata;
};

struct siging_info
{
    siging_info(uint64_t id, const cmp_key_persistency& persistency, bool positive_r) : platform_service(id, positive_r), signing_service(platform_service, persistency, signing_persistency) {}
    sign_platform platform_service;
    online_signing_persistency signing_persistency;
    cmp_ecdsa_online_signing_service signing_service;
};



static void ecdsa_sign(players_setup_info& players, cosigner_sign_algorithm type, const uint8_t* hashToSign, const size_t hashLen, ByteString& signature, const std::string& keyid)
{
    uuid_t uid;
    char txid[37] = {0};
    uuid_generate_random(uid);
    uuid_unparse(uid, txid);
    std::cout << "txid id = " << txid << std::endl;

    std::map<uint64_t, std::unique_ptr<siging_info>> services;
    std::set<uint64_t> players_ids;
    std::set<std::string> players_str;
    for (auto i = players.begin(); i != players.end(); ++i)
    {
        auto info = std::make_unique<siging_info>(i->first, i->second, false);
        services.emplace(i->first, move(info));
        players_ids.insert(i->first);
        players_str.insert(std::to_string(i->first));
    }

    signing_data data;
    memset(data.chaincode, '\0', 32);

    signing_block_data block;
    block.data.insert(block.data.begin(), hashToSign, hashToSign+hashLen);
    data.blocks.push_back(block);

    std::map<uint64_t, std::vector<cmp_mta_request>> mta_requests;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        COSIGNER_LOG(i->first, "Start signing");
        auto& request = mta_requests[i->first];
        i->second->signing_service.start_signing(keyid, txid, type, data, "", players_str, players_ids, request);
    }

    std::map<uint64_t, cmp_mta_responses> mta_responses;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        COSIGNER_LOG(i->first, "Compute MTA response");
        auto& response = mta_responses[i->first];
        i->second->signing_service.mta_response(txid, mta_requests, MPC_CMP_ONLINE_VERSION, response);
    }
    mta_requests.clear();

    std::map<uint64_t, std::vector<cmp_mta_deltas>> deltas;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        COSIGNER_LOG(i->first, "Verify MTA response");
        auto& delta = deltas[i->first];
        i->second->signing_service.mta_verify(txid, mta_responses, delta);
    }
    mta_responses.clear();

    std::map<uint64_t, std::vector<elliptic_curve_scalar>> sis;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        COSIGNER_LOG(i->first, "Compute si");
        auto& si = sis[i->first];
        i->second->signing_service.get_si(txid, deltas, si);
    }
    deltas.clear();

    std::vector<recoverable_signature> sigs;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        COSIGNER_LOG(i->first, "Compute final signature");
        i->second->signing_service.get_cmp_signature(txid, sis, sigs);
    }
    sis.clear();
    COSIGNER_RESET();
    memcpy(&signature[0], sigs[0].r, sizeof(elliptic_curve256_scalar_t));
    memcpy(&signature[sizeof(elliptic_curve256_scalar_t)], sigs[0].s, sizeof(elliptic_curve256_scalar_t));
}

#endif