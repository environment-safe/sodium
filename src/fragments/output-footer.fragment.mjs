}else{
  //don't fail in node, return a dummy
  globalThis._sodium = {
    crypto_auth: ()=>{},
    crypto_auth_verify: ()=>{},
    crypto_box_easy: ()=>{},
    crypto_box_keypair: ()=>{},
    crypto_box_open_easy: ()=>{},
    crypto_hash: ()=>{},
    crypto_hash_sha256: ()=>{},
    crypto_scalarmult: ()=>{},
    crypto_secretbox_easy: ()=>{},
    crypto_secretbox_open_easy: ()=>{},
    crypto_sign: ()=>{},
    crypto_sign_detached: ()=>{},
    crypto_sign_ed25519_pk_to_curve25519: ()=>{},
    crypto_sign_ed25519_sk_to_curve25519: ()=>{},
    crypto_sign_keypair: ()=>{},
    crypto_sign_open: ()=>{},
    crypto_sign_seed_keypair: ()=>{},
    crypto_sign_verify_detached: ()=>{},
    randombytes: ()=>{} 
  };
  globalThis._sodiumBuffer = {};
} //*/
export const crypto_auth= globalThis._sodium.crypto_auth;
export const crypto_auth_verify= globalThis._sodium.crypto_auth_verify;
export const crypto_box_easy= globalThis._sodium.crypto_box_easy;
export const crypto_box_keypair= globalThis._sodium.crypto_box_keypair;
export const crypto_box_open_easy= globalThis._sodium.crypto_box_open_easy;
export const crypto_hash= globalThis._sodium.crypto_hash;
export const crypto_hash_sha256= globalThis._sodium.crypto_hash_sha256;
export const crypto_scalarmult= globalThis._sodium.crypto_scalarmult;
export const crypto_secretbox_easy= globalThis._sodium.crypto_secretbox_easy;
export const crypto_secretbox_open_easy= globalThis._sodium.crypto_secretbox_open_easy;
export const crypto_sign= globalThis._sodium.crypto_sign;
export const crypto_sign_detached= globalThis._sodium.crypto_sign_detached;
export const crypto_sign_ed25519_pk_to_curve25519= globalThis._sodium.crypto_sign_ed25519_pk_to_curve25519;
export const crypto_sign_ed25519_sk_to_curve25519= globalThis._sodium.crypto_sign_ed25519_sk_to_curve25519;
export const crypto_sign_keypair= globalThis._sodium.crypto_sign_keypair;
export const crypto_sign_open= globalThis._sodium.crypto_sign_open;
export const crypto_sign_seed_keypair= globalThis._sodium.crypto_sign_seed_keypair;
export const crypto_sign_verify_detached= globalThis._sodium.crypto_sign_verify_detached;
export const randombytes_buf= globalThis._sodium.randombytes_buf;
export const crypto_sign_PUBLICKEYBYTES= globalThis._sodium.crypto_sign_PUBLICKEYBYTES;
export const crypto_sign_SECRETKEYBYTES= globalThis._sodium.crypto_sign_SECRETKEYBYTES;
export const crypto_sign_SEEDBYTES= globalThis._sodium.crypto_sign_SEEDBYTES;
export const CryptoBuffer = globalThis._sodiumBuffer;