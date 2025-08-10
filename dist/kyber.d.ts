import { MlKem512, MlKem768, MlKem1024 } from "mlkem";
declare const kyber_algorithms: {
    readonly kyber512: typeof MlKem512;
    readonly kyber768: typeof MlKem768;
    readonly kyber1024: typeof MlKem1024;
};
type KyberAlgorithm = keyof typeof kyber_algorithms;
declare class Kyber {
    private getCtx;
    get_keypair(algo: KyberAlgorithm, seed: Uint8Array): Promise<{
        public_key: Uint8Array;
        secret_key: Uint8Array;
    }>;
    get_keypair_hex(algo: KyberAlgorithm, seed: Uint8Array): Promise<{
        public_key: string;
        secret_key: string;
    }>;
    encapsulate(algo: KyberAlgorithm, public_key: Uint8Array): Promise<{
        cyphertext: Uint8Array;
        shared_secret: Uint8Array;
    }>;
    decapsulate(algo: KyberAlgorithm, cyphertext: Uint8Array, secret_key: Uint8Array): Promise<Uint8Array>;
}
export { Kyber };
export type { KyberAlgorithm };
//# sourceMappingURL=kyber.d.ts.map