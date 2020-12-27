<?php
/*
 * PSX is a open source PHP framework to develop RESTful APIs.
 * For the current version and informations visit <http://phpsx.org>
 *
 * Copyright 2010-2016 Christoph Kappestein <k42b3.x@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace PSX\OpenSsl;

/**
 * OpenSsl
 *
 * @author  Christoph Kappestein <k42b3.x@gmail.com>
 * @license http://www.apache.org/licenses/LICENSE-2.0
 * @link    http://phpsx.org
 */
class OpenSsl
{
    use ErrorHandleTrait;

    public static function decrypt(string $data, string $method, string $password, int $options = 1, string $iv = ''): string
    {
        return self::handleReturn(openssl_decrypt($data, $method, $password, $options, $iv));
    }

    public static function dhComputeKey(string $pubKey, PKey $dhKey): string
    {
        return self::handleReturn(openssl_dh_compute_key($pubKey, $dhKey->getResource()));
    }

    public static function digest(string $data, string $func, bool $rawOutput = false): string
    {
        return self::handleReturn(openssl_digest($data, $func, $rawOutput));
    }

    public static function encrypt(string $data, string $method, string $password, int $options = 0, string $iv = ''): string
    {
        return self::handleReturn(openssl_encrypt($data, $method, $password, $options, $iv));
    }

    public static function errorString()
    {
        return openssl_error_string();
    }

    public static function getCertLocations(): array
    {
        return openssl_get_cert_locations();
    }

    public static function getCipherIvLength(string $method): int
    {
        return self::handleReturn(openssl_cipher_iv_length($method));
    }

    public static function getCipherMethods(bool $aliases = false): array
    {
        return openssl_get_cipher_methods($aliases);
    }

    public static function getCurveNames(): array
    {
        return openssl_get_curve_names();
    }

    public static function getMdMethods(bool $aliases = false): array
    {
        return openssl_get_md_methods($aliases);
    }

    public static function open(string $sealedData, ?string &$openData, string $envKey, PKey $key, string $method = 'RC4', string $iv = ''): bool
    {
        return self::handleReturn(openssl_open($sealedData, $openData, $envKey, $key->getResource(), $method, $iv));
    }

    public static function privateDecrypt(string $data, ?string &$decrypted, PKey $key, int $padding = OPENSSL_PKCS1_PADDING): bool
    {
        return self::handleReturn(openssl_private_decrypt($data, $decrypted, $key->getResource(), $padding));
    }

    public static function privateEncrypt(string $data, ?string &$crypted, PKey $key, int $padding = OPENSSL_PKCS1_PADDING): bool
    {
        return self::handleReturn(openssl_private_encrypt($data, $crypted, $key->getResource(), $padding));
    }

    public static function publicDecrypt(string $data, ?string &$decrypted, PKey $key, int $padding = OPENSSL_PKCS1_PADDING): bool
    {
        return self::handleReturn(openssl_public_decrypt($data, $decrypted, $key->getPublicKey(), $padding));
    }

    public static function publicEncrypt(string $data, ?string &$crypted, PKey $key, int $padding = OPENSSL_PKCS1_PADDING): bool
    {
        return self::handleReturn(openssl_public_encrypt($data, $crypted, $key->getPublicKey(), $padding));
    }

    public static function randomPseudoBytes(int $length): string
    {
        return self::handleReturn(openssl_random_pseudo_bytes($length));
    }

    public static function seal(string $data, ?string &$sealedData, ?array &$envKeys, array $pubKeys, string $method = 'RC4', string $iv = ''): int
    {
        $pubKeyIds = array();
        foreach ($pubKeys as $pubKey) {
            if ($pubKey instanceof PKey) {
                $pubKeyIds[] = $pubKey->getPublicKey();
            } else {
                throw new Exception('Pub keys must be an array containing PSX\OpenSsl\PKey instances');
            }
        }

        return self::handleReturn(openssl_seal($data, $sealedData, $envKeys, $pubKeyIds, $method, $iv));
    }

    public static function sign(string $data, ?string &$signature, PKey $key, int $signatureAlg = OPENSSL_ALGO_SHA1): bool
    {
        return self::handleReturn(openssl_sign($data, $signature, $key->getResource(), $signatureAlg));
    }

    public static function verify(string $data, string $signature, PKey $key, int $signatureAlg = OPENSSL_ALGO_SHA1): int
    {
        return openssl_verify($data, $signature, $key->getPublicKey(), $signatureAlg);
    }
}
