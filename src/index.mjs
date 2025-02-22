/* global Buffer:false */
import { isBrowser, isJsDom } from 'browser-or-node';
import * as mod from 'module';
//import * as path from 'path';
// would prefer to not load in node (it is unused), but it would require an async load
import * as sd from '../dist/browserify/index.mjs';
let internalRequire = null;
if(typeof require !== 'undefined') internalRequire = require;
const ensureRequire = ()=> (!internalRequire) && (internalRequire = mod.createRequire(import.meta.url));

let sodium = {};
if( isBrowser || isJsDom){
    sodium = sd;
}else{
    ensureRequire();
    sodium = internalRequire('sodium-universal');
    sodium.CryptoBuffer = Buffer;
}
//process.exit();

export const {
    crypto_auth,
    crypto_auth_verify,
    crypto_box_easy,
    crypto_box_keypair,
    crypto_box_open_easy,
    crypto_hash,
    crypto_hash_sha256,
    crypto_scalarmult,
    crypto_secretbox_easy,
    crypto_secretbox_open_easy,
    crypto_sign,
    crypto_sign_detached,
    crypto_sign_ed25519_pk_to_curve25519,
    crypto_sign_ed25519_sk_to_curve25519,
    crypto_sign_keypair,
    crypto_sign_open,
    crypto_sign_seed_keypair,
    crypto_sign_verify_detached,
    crypto_secretbox_MACBYTES,
    crypto_sign_PUBLICKEYBYTES,
    crypto_sign_SECRETKEYBYTES,
    crypto_sign_SEEDBYTES,
    crypto_sign_BYTES,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
    randombytes_buf,
    CryptoBuffer
} = sodium;
 
