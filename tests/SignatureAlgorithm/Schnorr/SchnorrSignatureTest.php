<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature\Algorithm;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\SS256K;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 *
 * @coversNothing
 */
final class SchnorrSignatureTest extends TestCase
{
    private function getKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => 'secp256k1',
            'd'   => Base64UrlSafe::encodeUnpadded(
                hex2bin('D1592A94BBB9B5D94CDC425FC7DA80B6A47863AE973A9D581FD9D8F29690B659')
            ),
            'x' => Base64UrlSafe::encodeUnpadded(
                hex2bin('4B4DF318DE05BB8F3A115BF337F9BCBC55CA14B917B46BCB557D3C9A158D4BE0')
            ),
            'y' => Base64UrlSafe::encodeUnpadded(
                hex2bin('627EB75731A8BBEBC7D9A3C57EC4D7DA2CBA6D2A28E7F45134921861FE1CF5D9')
            ),
        ]);
    }

    public function testInvalidKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Wrong key type.');
        $key = new JWK([
            'kty' => 'RSA',
        ]);

        $schnorr = new SS256K();
        $data    = 'Live long and Prosper.';

        $schnorr->sign($key, $data);
    }

    public function testKeyNotPrivate(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The EC key is not a private key.');

        $key = $this->getKey();

        // get public key form
        $publicKey = $key->toPublic();

        $schnorr = new SS256K();

        $data = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $schnorr->sign($publicKey, $data);
    }

    public function testSS256KSignVerify(): void
    {
        $key     = $this->getKey();
        $schnorr = new SS256K();
        $data    = 'Live long and Prosper.';

        $signature = $schnorr->sign($key, $data);

        static::assertTrue($schnorr->verify($key, $data, $signature));
    }

    public function testBadSignature(): void
    {
        $key     = $this->getKey();
        $schnorr = new SS256K();

        $data      = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $signature = 'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0';

        static::assertFalse($schnorr->verify($key, $data, $signature));
    }
}
