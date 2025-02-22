/* global describe:false */
import { chai } from '@environment-safe/chai';
import { it } from '@open-automaton/moka';
import * as sodium from '../src/index.mjs';
const should = chai.should();
const CryptoBuffer = sodium.CryptoBuffer;

//import { data } from './data/test-data.mjs';

const fnNames = [
    'crypto_auth',
    'crypto_auth_verify',
    'crypto_box_easy',
    'crypto_box_keypair',
    'crypto_box_open_easy',
    'crypto_hash',
    'crypto_hash_sha256',
    'crypto_scalarmult',
    'crypto_secretbox_easy',
    'crypto_secretbox_open_easy',
    'crypto_sign',
    'crypto_sign_detached',
    'crypto_sign_ed25519_pk_to_curve25519',
    'crypto_sign_ed25519_sk_to_curve25519',
    'crypto_sign_keypair',
    'crypto_sign_open',
    'crypto_sign_seed_keypair',
    'crypto_sign_verify_detached',
    'randombytes_buf'
];

describe('module', ()=>{
    
    describe('guarantee member presence', ()=>{
        fnNames.forEach((fnName)=>{
            it(`sodium.${fnName}() is present`, ()=>{
                should.exist(sodium[fnName]);
            });
        });
    });
    
    describe('basic tests', ()=>{
        it('can produce random bytes', ()=>{
            var rnd = CryptoBuffer.allocUnsafe(12);
            var rnd2 = CryptoBuffer.allocUnsafe(12); // Cryptographically random data
            sodium.randombytes_buf(rnd);
            sodium.randombytes_buf(rnd2);
            rnd.toString('hex').should.not.equal(rnd2.toString('hex'));
        });
    });
    
    describe('performs a simple test suite', ()=>{
        
        it('sodium-javascript #1', ()=>{
            const pk = CryptoBuffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
            const sk = CryptoBuffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
            const seed = CryptoBuffer.alloc(sodium.crypto_sign_SEEDBYTES, 'lo');
            
            try{
                sodium.crypto_sign_seed_keypair();
                should.not.exist(new Error(
                    'signed keypair with empty arguments'
                ));
                // eslint-disable-next-line no-empty
            }catch{}
            
            try{
                sodium.crypto_sign_seed_keypair(
                    CryptoBuffer.alloc(0), CryptoBuffer.alloc(0), CryptoBuffer.alloc(0)
                );
                should.not.exist(new Error(
                    'signed keypair with empty arguments'
                ));
                // eslint-disable-next-line no-empty
            }catch{}
            
            sodium.crypto_sign_seed_keypair(pk, sk, seed);
            
            const eSk = '6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f41eb5b4dba29b19e391d9a4d1a4a879b27958ff3734e10cfbf1f46d68f4d3038';
            const ePk = '41eb5b4dba29b19e391d9a4d1a4a879b27958ff3734e10cfbf1f46d68f4d3038';
            
            pk.toString('hex').should.equal(ePk, 'seeded public key');
            sk.toString('hex').should.equal(eSk, 'seeded secret key');
        });
        
        it('chloride-tests #1', ()=>{
            const pk = CryptoBuffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
            const sk = CryptoBuffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
            const seed = Uint8Array.from(
                atob('K9gGyX8OAK8aH8Myj6djqSaXI8jbj6xPk69x2xhtbpA='), 
                c => c.charCodeAt(0)
            );
            
            sodium.crypto_sign_seed_keypair(pk, sk, seed);
            
            const values = {
                publicKey: '1b9KP8znF7A4i8wnSevBSK2ZabI/Re4bYF/Vh3hXasQ=',
                secretKey: 'K9gGyX8OAK8aH8Myj6djqSaXI8jbj6xPk69x2xhtbpDVv0o/zOcXsDiLzCdJ68FIrZlpsj9F7htgX9WHeFdqxA=='
            };
            
            pk.toString('base64').should.equal(values.publicKey, 'seeded public key');
            sk.toString('base64').should.equal(values.secretKey, 'seeded secret key');
        });
        
        it('chloride-tests #2', ()=>{
            const pk = CryptoBuffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
            const sk = CryptoBuffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
            const seed = Uint8Array.from(
                atob('gbY32PzSxtpjWeaWMROhFw3nleS3JbhNHgtM/Z7FjOk='), 
                c => c.charCodeAt(0)
            );
            
            sodium.crypto_sign_seed_keypair(pk, sk, seed);
            
            const values = {
                publicKey: '7MG1hyfz8SsxlIgansud4LKM57IHIw2Okw/hvOdeJWw=',
                secretKey: 'gbY32PzSxtpjWeaWMROhFw3nleS3JbhNHgtM/Z7FjOnswbWHJ/PxKzGUiBqey53gsoznsgcjDY6TD+G8514lbA=='
            };
            
            pk.toString('base64').should.equal(values.publicKey, 'seeded public key');
            sk.toString('base64').should.equal(values.secretKey, 'seeded public key');
        });
        
        it.skip('chloride-tests #3', ()=>{
            /*const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
            const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
            
            sodium.crypto_sign_keypair(pk, sk)
            
            const message = Buffer.from('Hello, World!')
            const signature = Buffer.alloc(sodium.crypto_sign_BYTES)
            
            sodium.crypto_sign_detached(signature, message, sk)
            //*/
            const sig = CryptoBuffer.alloc(sodium.crypto_sign_BYTES);
            const sk = new Uint8Array(
                atob('dHJ1c3QgYnV0IHZlcmlmeQ==')
            );
            const m = Uint8Array.from(
                atob('gbY32PzSxtpjWeaWMROhFw3nleS3JbhNHgtM/Z7FjOnswbWHJ/PxKzGUiBqey53gsoznsgcjDY6TD+G8514lbA=='), 
                c => c.charCodeAt(0)
            );
            
            sodium.crypto_sign_detached(sig, m, sk);
            
            const value = 'Pjr1v5BTjtCUcGrxtzkdLJJh5/o8cnqWbkQZ7uxx9IItIyqj3cR+DGZbWNcHkpNhU4ZWSI1ndX++/boY8s7LCw==';
            
            sig.toString('base64').should.equal(value, 'sig');
        });
    });
});

