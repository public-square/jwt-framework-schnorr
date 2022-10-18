<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use Exception;
use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Mdanter\Ecc\Crypto\Signature\SchnorrSignature;
use ParagonIE\ConstantTime\Base64UrlSafe;

abstract class Schnorr implements SignatureAlgorithm
{
    public function allowedKeyTypes(): array
    {
        return ['EC'];
    }

    public function sign(JWK $key, string $input): string
    {
        $this->checkKey($key);

        if (!$key->has('d')) {
            throw new InvalidArgumentException('The EC key is not a private key.');
        }

        try {
            // TODO: verify if works as below or needs to be changed to $key->get('d');
            $d = bin2hex(Base64UrlSafe::decodeNoPadding($key->get('d')));

            $schnorrSig = (new SchnorrSignature())->sign($d, $input);

            return $schnorrSig['signature'];
        } catch (\Exception $e) {
            throw new Exception($e->getMessage());
        }
    }

    public function verify(JWK $key, string $input, string $signature): bool
    {
        $this->checkKey($key);

        $publicKey = $key->toPublic();

        $jwss = new CompactSerializer();

        $jws = $jwss->unserialize($input . '.' . $signature);

        $message = json_decode($jws->getPayload());

        $publicKeyHex = $publicKey->get('x');

        try {
            return (new SchnorrSignature())->verify($publicKeyHex, $signature, $message);
        } catch (\Exception $e) {
            throw new Exception($e->getMessage());
        }
    }

    abstract protected function getHashAlgorithm(): string;

    abstract protected function getSignaturePartLength(): int;

    private function checkKey(JWK $key): void
    {
        if (!\in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidArgumentException('Wrong key type.');
        }
        foreach (['x', 'y', 'crv'] as $k) {
            if (!$key->has($k)) {
                throw new InvalidArgumentException(sprintf('The key parameter "%s" is missing.', $k));
            }
        }
    }
}
