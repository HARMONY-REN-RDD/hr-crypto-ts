import { KyberAlgorithm } from './kyber';
import { HashAlgorithm } from "./hashing";
import { DilithiumAlgorithm, HexKeyPair, KeyPair } from './dilithium';
export default class HarmonyCrypto {
    static hash(data: string, algo: HashAlgorithm): Uint8Array;
    static hash_hex(data: string, algo: HashAlgorithm): string;
    static hkdf_derive(seed: Uint8Array, salt: Uint8Array, info: string, length: number): Promise<Uint8Array>;
    get_kyber_kypair(algo: KyberAlgorithm, seed: Uint8Array, info?: string): Promise<{
        public_key: Uint8Array;
        secret_key: Uint8Array;
    }>;
    get_kyber_keypair_hex(algo: KyberAlgorithm, seed: Uint8Array): Promise<{
        public_key: string;
        secret_key: string;
    }>;
    kyber_encapsulate(algo: KyberAlgorithm, public_key: Uint8Array): Promise<{
        cyphertext: Uint8Array;
        shared_secret: Uint8Array;
    }>;
    kyber_decapsulate(algo: KyberAlgorithm, msg: Uint8Array, secret_key: Uint8Array): Promise<Uint8Array>;
    get_dilithium_keypair(algo: DilithiumAlgorithm, seed: Uint8Array, info?: string): Promise<KeyPair>;
    get_dilithium_keypair_hex(seed: Uint8Array, algo: DilithiumAlgorithm): Promise<HexKeyPair>;
    dilithium_sign(msg: Uint8Array, secret_key: Uint8Array, algo: DilithiumAlgorithm): Promise<Uint8Array>;
    dilithium_verify(signature: Uint8Array, msg: Uint8Array, public_key: Uint8Array, algo: DilithiumAlgorithm): Promise<boolean>;
}
//# sourceMappingURL=index.d.ts.map