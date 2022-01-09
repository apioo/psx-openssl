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

namespace PSX\OpenSsl\Tests;

use PHPUnit\Framework\TestCase;
use PSX\OpenSsl\Exception\OpenSslException;
use PSX\OpenSsl\PKey;

/**
 * PKeyTest
 *
 * @author  Christoph Kappestein <christoph.kappestein@gmail.com>
 * @license http://www.apache.org/licenses/LICENSE-2.0
 * @link    https://phpsx.org
 */
class PKeyTest extends TestCase
{
    public function testExport()
    {
        $pkey = new PKey();
        $pkey->export($privateKey, 'foobar');

        $publicKey = $pkey->getPublicKey();

        $this->assertEquals('-----BEGIN PUBLIC KEY-----', substr($publicKey, 0, 26));
    }

    public function testGetPrivate()
    {
        $privateKey = file_get_contents(__DIR__ . '/private.pem');

        $pkey = PKey::newPrivate($privateKey, 'foobar');

        $this->assertInstanceOf(PKey::class, $pkey);

        $publicKey = $pkey->getPublicKey();

        $this->assertEquals('-----BEGIN PUBLIC KEY-----', substr($publicKey, 0, 26));
    }

    public function testGetPrivateInvalidPassword()
    {
        $this->expectException(OpenSslException::class);

        $privateKey = file_get_contents(__DIR__ . '/private.pem');

        PKey::newPrivate($privateKey, 'foo');
    }

    public function testGetPrivateInvalidFormat()
    {
        $this->expectException(OpenSslException::class);

        $privateKey = <<<TEXT
-----BEGIN RSA PRIVATE KEY-----
foobar
-----END RSA PRIVATE KEY-----
TEXT;

        PKey::newPrivate($privateKey, 'foobar');
    }

    public function testGetPublic()
    {
        $publicKey = file_get_contents(__DIR__ . '/public.pem');

        $pkey = PKey::newPublic($publicKey);

        $this->assertInstanceOf(PKey::class, $pkey);

        $publicKey = $pkey->getPublicKey();

        $this->assertEquals('-----BEGIN PUBLIC KEY-----', substr($publicKey, 0, 26));
    }

    public function testGetPublicInvalidFormat()
    {
        $this->expectException(OpenSslException::class);

        $publicKey = <<<TEXT
-----BEGIN PUBLIC KEY-----
foobar
-----END PUBLIC KEY-----
TEXT;

        PKey::newPublic($publicKey);
    }
}
