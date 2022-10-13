<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

final class SS256K extends Schnorr
{
    public function name(): string
    {
        return 'SS256K';
    }

    protected function getHashAlgorithm(): string
    {
        return 'sha256';
    }

    protected function getSignaturePartLength(): int
    {
        return 64;
    }
}
