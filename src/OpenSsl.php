<?php
/*
 * PSX is an open source PHP framework to develop RESTful APIs.
 * For the current version and information visit <https://phpsx.org>
 *
 * Copyright 2010-2022 Christoph Kappestein <christoph.kappestein@gmail.com>
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

use PSX\OpenSsl\Exception\OpenSslException;

/**
 * OpenSsl
 *
 * @author  Christoph Kappestein <christoph.kappestein@gmail.com>
 * @license http://www.apache.org/licenses/LICENSE-2.0
 * @link    https://phpsx.org
 */
class OpenSsl
{
    use ErrorHandleTrait;

    /**
     * @throws OpenSslException
     */
    public static function decrypt(string $data, string $method, string $password, int $options = 1, string $iv = ''): string
    {
        return self::throwExceptionOnFalse(openssl_decrypt($data, $method, $password, $options, $iv));
    }

    /**
     * @throws OpenSslException
     */
    public static function dhComputeKey(string $pubKey, PKey $dhKey): string
    {
        return self::throwExceptionOnFalse(openssl_dh_compute_key($pubKey, $dhKey->getResource()));
    }

    /**
     * @throws OpenSslException
     */
    public static function digest(string $data, string $func, bool $rawOutput = false): string
    {
        return self::throwExceptionOnFalse(openssl_digest($data, $func, $rawOutput));
    }

    /**
     * @throws OpenSslException
     */
    public static function encrypt(string $data, string $method, string $password, int $options = 0, string $iv = ''): string
    {
        return self::throwExceptionOnFalse(openssl_encrypt($data, $method, $password, $options, $iv));
    }

    public static function errorString(): string|false
    {
        return openssl_error_string();
    }

    public static function getCertLocations(): array
    {
        return openssl_get_cert_locations();
    }

    /**
     * @throws OpenSslException
     */
    public static function getCipherIvLength(string $method): int
    {
        return self::throwExceptionOnFalse(openssl_cipher_iv_length($method));
    }

    public static function getCipherMethods(bool $aliases = false): array
    {
        return openssl_get_cipher_methods($aliases);
    }

    public static function getCurveNames(): array
    {
        return openssl_get_curve_names() ?: [];
    }

    public static function getMdMethods(bool $aliases = false): array
    {
        return openssl_get_md_methods($aliases);
    }

    /**
     * @throws OpenSslException
     */
    public static function open(string $sealedData, ?string &$openData, string $envKey, PKey $key, string $method = 'AES256', ?string $iv = null): bool
    {
        if ($iv === null) {
            $iv = openssl_random_pseudo_bytes(32);
        }

        return self::throwExceptionOnFalse(openssl_open($sealedData, $openData, $envKey, $key->getResource(), $method, $iv));
    }

    /**
     * @throws OpenSslException
     */
    public static function privateDecrypt(string $data, ?string &$decrypted, PKey $key, int $padding = OPENSSL_PKCS1_PADDING): bool
    {
        return self::throwExceptionOnFalse(openssl_private_decrypt($data, $decrypted, $key->getResource(), $padding));
    }

    /**
     * @throws OpenSslException
     */
    public static function privateEncrypt(string $data, ?string &$crypted, PKey $key, int $padding = OPENSSL_PKCS1_PADDING): bool
    {
        return self::throwExceptionOnFalse(openssl_private_encrypt($data, $crypted, $key->getResource(), $padding));
    }

    /**
     * @throws OpenSslException
     */
    public static function publicDecrypt(string $data, ?string &$decrypted, PKey $key, int $padding = OPENSSL_PKCS1_PADDING): bool
    {
        return self::throwExceptionOnFalse(openssl_public_decrypt($data, $decrypted, $key->getPublicKey(), $padding));
    }

    /**
     * @throws OpenSslException
     */
    public static function publicEncrypt(string $data, ?string &$crypted, PKey $key, int $padding = OPENSSL_PKCS1_PADDING): bool
    {
        return self::throwExceptionOnFalse(openssl_public_encrypt($data, $crypted, $key->getPublicKey(), $padding));
    }

    /**
     * @throws OpenSslException
     */
    public static function randomPseudoBytes(int $length): string
    {
        return self::throwExceptionOnFalse(openssl_random_pseudo_bytes($length));
    }

    /**
     * @throws OpenSslException
     */
    public static function seal(string $data, ?string &$sealedData, ?array &$envKeys, array $pubKeys, string $method = 'AES256', ?string $iv = null): int
    {
        $pubKeyIds = array();
        foreach ($pubKeys as $pubKey) {
            if ($pubKey instanceof PKey) {
                $pubKeyIds[] = $pubKey->getPublic()->getResource();
            } else {
                throw new OpenSslException('Pub keys must be an array containing PSX\OpenSsl\PKey instances');
            }
        }

        if ($iv === null) {
            $iv = openssl_random_pseudo_bytes(32);
        }

        return self::throwExceptionOnFalse(openssl_seal($data, $sealedData, $envKeys, $pubKeyIds, $method, $iv));
    }

    /**
     * @throws OpenSslException
     */
    public static function sign(string $data, ?string &$signature, PKey $key, int $signatureAlg = OPENSSL_ALGO_SHA1): bool
    {
        return self::throwExceptionOnFalse(openssl_sign($data, $signature, $key->getResource(), $signatureAlg));
    }

    /**
     * @throws OpenSslException
     */
    public static function verify(string $data, string $signature, PKey $key, int $signatureAlg = OPENSSL_ALGO_SHA1): int
    {
        return self::throwExceptionOnFalse(openssl_verify($data, $signature, $key->getPublicKey(), $signatureAlg));
    }
}
