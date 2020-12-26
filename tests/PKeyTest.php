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

namespace PSX\OpenSsl\Tests;

use PHPUnit\Framework\TestCase;
use PSX\OpenSsl\Exception;
use PSX\OpenSsl\PKey;

/**
 * PKeyTest
 *
 * @author  Christoph Kappestein <k42b3.x@gmail.com>
 * @license http://www.apache.org/licenses/LICENSE-2.0
 * @link    http://phpsx.org
 */
class PKeyTest extends TestCase
{
    protected function setUp(): void
    {
        if (!function_exists('openssl_pkey_new')) {
            $this->markTestSkipped('Openssl extension not installed');
        }
    }

    public function testExport()
    {
        $pkey = new PKey();
        $pkey->export($privateKey, 'foobar');

        $publicKey = $pkey->getPublicKey();

        $pkey->free();

        $this->assertEquals('-----BEGIN PUBLIC KEY-----', substr($publicKey, 0, 26));
    }

    public function testGetPrivate()
    {
        $privateKey = <<<TEXT
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,AA056EDD41D3832C

fhMA8lDIGNiwdczPT8YZDCnDV6M8+mmpLCEOOVzLt68ecGJoNk0BADhN3BgXsmXe
pKkWdfVLco5FVwMJaFx21Kh9EmZWu9yRDJ1GMSn9HwPYdjm2v9lvPPoz2ELtqz9C
MjqLt7bU/YVKhy/bPVGoQPzO36Esj6qVhlQX7DhkCIf8ZrG8rYJFszn3B/9TaJ8/
CGf85F8tJ20/DOh+WQZI0wB53Plvpq/YX7JbTEgQV3YlCv4UZrCYl5TEBffv3CLL
Z+KBJ3u50LAWpouBY0Ljw+h0VeOODynq6dNzT/C60PwazZFqFzPijkTu021cTosc
7LwWL5hoOhcYDBI9SCS3PbRAqDWGwRR98SBzDg9I2MK59AgAuul+cSTKqCbgSZi1
VdL+uzmM6n5hnzn5gDF5pLNOjlp/Omwb6m49gmJ0LtdQCXqFPmafHW5QsAIPdVzT
veZuoE2NsQXnEpkqaq/lZlF8n+4I5ES8QlQByfEubRAtz2jaAJMB570CIVbtgt3r
PNLYJ0kV1uHAhNxuvfSIoIsFuHEgz+QXzDB4qync0JTomiNaVvRDjJzYwWe+CYmg
rnUEO3CnjigrCzVnI4HzJn9uWwzJ3y1ayHV914BM+gjaMRfFCA5Am0e5ci+7cnU+
CRTn3xyYESJdMy8ot7wiScI0NOSM8p4ph01OrZWWz8UxZNgDgorh9/2l9U0ugcfW
6BSmVPYWgtl4Yhh3umw2fP9/EIkULFNx/XSKzWkFbpvqAbnv80qZbl46Di94U8rj
P2CvWELxGmAIxoZ75XLIGoEoAN9mphs/Q1fUaawt7cRGuheH3usG7d/5a9EtL/GZ
Jvoqv3GdFtv0SHWxrHkArFTxqONwciu91NrGbUa2vFz2+bAS+egVRHVL5CdNzW5T
kVuneyHLqi/zvYrvpBN81ZV78ouWZzS7mYf/JwiUpkTpEFDSvGzy+ojYV5PPwmPV
esgz6lNUnPmCDDfwhgobYMIRT7mWXESBZKCqT2Nk4SvDaSSEfAhc44zKMFvGjznO
jnXuSM9PVh2G9ht0Ma+SaXmctKB5Zs4ym9cgFV1xWSYzUxpOuKc8ICdZAG8yuOL7
spUrwrYn1VHK+o11QOBHVnMsT4UUULTDfn2mTy5hrJDlDsSYOjZ8y72siB33b0zB
pmP6xYUm5NAtzmE0nPsCbyb+quTsTtbRIrdnGhCKXMRqZdEo+86M+eEGB8itRyE0
t5fscBw74mYagVOK2a8146B21LxcqCVkgheUaBBft1A629Ak9+Z8afpGXZ016tbV
zbDgV4LuEHuqW/HX/hyIHSBzh8sa96jpIvkFu3naxddDe0X4RZVO1CdDUyUUJg4P
5XgkAC+mmNLIcOvcbcfoZ5bnIyNv+ZaJgcU1Juh7LM/b9hYvuYSqYqsURFGzv2x9
lXSA/M7YcS8vXaNVfqINhZn9LFM9mQQ152cdMA1bmoUBeFvy8cMx86IPbOlql49S
tBc/hOSY90sjSkTIrX6V0GcHBp50z9j2pnSz66q4opo9/vPIXU4CDiC73OuQudZz
0CxBi7jJ0PeTN2CaDCYJJ7xG0ut7kGxXS0C9PFpzy+YLLRoNc0hdHnJMidyc1sgA
-----END RSA PRIVATE KEY-----
TEXT;

        $pkey = PKey::getPrivate($privateKey, 'foobar');

        $this->assertInstanceOf(PKey::class, $pkey);

        $publicKey = $pkey->getPublicKey();

        $pkey->free();

        $this->assertEquals('-----BEGIN PUBLIC KEY-----', substr($publicKey, 0, 26));
    }

    public function testGetPrivateInvalidPassword()
    {
        $this->expectException(Exception::class);

        $privateKey = <<<TEXT
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,AA056EDD41D3832C

fhMA8lDIGNiwdczPT8YZDCnDV6M8+mmpLCEOOVzLt68ecGJoNk0BADhN3BgXsmXe
pKkWdfVLco5FVwMJaFx21Kh9EmZWu9yRDJ1GMSn9HwPYdjm2v9lvPPoz2ELtqz9C
MjqLt7bU/YVKhy/bPVGoQPzO36Esj6qVhlQX7DhkCIf8ZrG8rYJFszn3B/9TaJ8/
CGf85F8tJ20/DOh+WQZI0wB53Plvpq/YX7JbTEgQV3YlCv4UZrCYl5TEBffv3CLL
Z+KBJ3u50LAWpouBY0Ljw+h0VeOODynq6dNzT/C60PwazZFqFzPijkTu021cTosc
7LwWL5hoOhcYDBI9SCS3PbRAqDWGwRR98SBzDg9I2MK59AgAuul+cSTKqCbgSZi1
VdL+uzmM6n5hnzn5gDF5pLNOjlp/Omwb6m49gmJ0LtdQCXqFPmafHW5QsAIPdVzT
veZuoE2NsQXnEpkqaq/lZlF8n+4I5ES8QlQByfEubRAtz2jaAJMB570CIVbtgt3r
PNLYJ0kV1uHAhNxuvfSIoIsFuHEgz+QXzDB4qync0JTomiNaVvRDjJzYwWe+CYmg
rnUEO3CnjigrCzVnI4HzJn9uWwzJ3y1ayHV914BM+gjaMRfFCA5Am0e5ci+7cnU+
CRTn3xyYESJdMy8ot7wiScI0NOSM8p4ph01OrZWWz8UxZNgDgorh9/2l9U0ugcfW
6BSmVPYWgtl4Yhh3umw2fP9/EIkULFNx/XSKzWkFbpvqAbnv80qZbl46Di94U8rj
P2CvWELxGmAIxoZ75XLIGoEoAN9mphs/Q1fUaawt7cRGuheH3usG7d/5a9EtL/GZ
Jvoqv3GdFtv0SHWxrHkArFTxqONwciu91NrGbUa2vFz2+bAS+egVRHVL5CdNzW5T
kVuneyHLqi/zvYrvpBN81ZV78ouWZzS7mYf/JwiUpkTpEFDSvGzy+ojYV5PPwmPV
esgz6lNUnPmCDDfwhgobYMIRT7mWXESBZKCqT2Nk4SvDaSSEfAhc44zKMFvGjznO
jnXuSM9PVh2G9ht0Ma+SaXmctKB5Zs4ym9cgFV1xWSYzUxpOuKc8ICdZAG8yuOL7
spUrwrYn1VHK+o11QOBHVnMsT4UUULTDfn2mTy5hrJDlDsSYOjZ8y72siB33b0zB
pmP6xYUm5NAtzmE0nPsCbyb+quTsTtbRIrdnGhCKXMRqZdEo+86M+eEGB8itRyE0
t5fscBw74mYagVOK2a8146B21LxcqCVkgheUaBBft1A629Ak9+Z8afpGXZ016tbV
zbDgV4LuEHuqW/HX/hyIHSBzh8sa96jpIvkFu3naxddDe0X4RZVO1CdDUyUUJg4P
5XgkAC+mmNLIcOvcbcfoZ5bnIyNv+ZaJgcU1Juh7LM/b9hYvuYSqYqsURFGzv2x9
lXSA/M7YcS8vXaNVfqINhZn9LFM9mQQ152cdMA1bmoUBeFvy8cMx86IPbOlql49S
tBc/hOSY90sjSkTIrX6V0GcHBp50z9j2pnSz66q4opo9/vPIXU4CDiC73OuQudZz
0CxBi7jJ0PeTN2CaDCYJJ7xG0ut7kGxXS0C9PFpzy+YLLRoNc0hdHnJMidyc1sgA
-----END RSA PRIVATE KEY-----
TEXT;

        PKey::getPrivate($privateKey, 'foo');
    }

    public function testGetPrivateInvalidFormat()
    {
        $this->expectException(Exception::class);

        $privateKey = <<<TEXT
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,AA056EDD41D3832C

fhMA8lDIGNiwdczPT8YZDCnDV6M8+mmpLCEOOVzLt68ecGJoNk0BADhN3BgXsmXe
pKkWdfVLco5FVwMJaFx21Kh9EmZWu9yRDJ1GMSn9HwPYdjm2v9lvPPoz2ELtqz9C
MjqLt7bU/YVKhy/bPVGoQPzO36Esj6qVhlQX7DhkCIf8ZrG8rYJFszn3B/9TaJ8/
CGf85F8tJ20/DOh+WQZI0wB53Plvpq/YX7JbTEgQV3YlCv4UZrCYl5TEBffv3CLL
Z+KBJ3u50LAWpouBY0Ljw+h0VeOODynq6dNzT/C60PwazZFqFzPijkTu021cTosc
7LwWL5hoOhcYDBI9SCS3PbRAqDWGwRR98SBzDg9I2MK59AgAuul+cSTKqCbgSZi1
VdL+uzmM6n5hnzn5gDF5pLNOjlp/Omwb6m49gmJ0LtdQCXqFPmafHW5QsAIPdVzT
veZuoE2NsQXnEpkqaq/lZlF8n+4I5ES8QlQByfEubRAtz2jaAJMB570CIVbtgt3r
PNLYJ0kV1uHAhNxuvfSIoIsFuHEgz+QXzDB4qync0JTomiNaVvRDjJzYwWe+CYmg
rnUEO3CnjigrCzVnI4HzJn8uWwzJ3y1ayHV914BM+gjaMRfFCA5Am0e5ci+7cnU+
CRTn3xyYESJdMy8ot7wiScI0NOSM8p4ph01OrZWWz8UxZNgDgorh9/2l9U0ugcfW
6BSmVPYWgtl4Yhh3umw2fP9/EIkULFNx/XSKzWkFbpvqAbnv80qZbl46Di94U8rj
P2CvWELxGmAIxoZ75XLIGoEoAN9mphs/Q1fUaawt7cRGuheH3usG7d/5a9EtL/GZ
Jvoqv3GdFtv0SHWxrHkArFTxqONwciu91NrGbUa2vFz2+bAS+egVRHVL5CdNzW5T
kVuneyHLqi/zvYrvpBN81ZV78ouWZzS7mYf/JwiUpkTpEFDSvGzy+ojYV5PPwmPV
esgz6lNUnPmCDDfwhgobYMIRT7mWXESBZKCqT2Nk4SvDaSSEfAhc44zKMFvGjznO
jnXuSM9PVh2G9ht0Ma+SaXmctKB5Zs4ym9cgFV1xWSYzUxpOuKc8ICdZAG8yuOL7
spUrwrYn1VHK+o11QOBHVnMsT4UUULTDfn2mTy5hrJDlDsSYOjZ8y72siB33b0zB
pmP6xYUm5NAtzmE0nPsCbyb+quTsTtbRIrdnGhCKXMRqZdEo+86M+eEGB8itRyE0
t5fscBw74mYagVOK2a8146B21LxcqCVkgheUaBBft1A629Ak9+Z8afpGXZ016tbV
zbDgV4LuEHuqW/HX/hyIHSBzh8sa96jpIvkFu3naxddDe0X4RZVO1CdDUyUUJg4P
5XgkAC+mmNLIcOvcbcfoZ5bnIyNv+ZaJgcU1Juh7LM/b9hYvuYSqYqsURFGzv2x9
lXSA/M7YcS8vXaNVfqINhZn9LFM9mQQ152cdMA1bmoUBeFvy8cMx86IPbOlql49S
tBc/hOSY90sjSkTIrX6V0GcHBp50z9j2pnSz66q4opo9/vPIXU4CDiC73OuQudZz
0CxBi7jJ0PeTN2CaDCYJJ7xG0ut7kGxXS0C9PFpzy+YLLRoNc0hdHnJMidyc1sgA
-----END RSA PRIVATE KEY-----
TEXT;

        PKey::getPrivate($privateKey, 'foobar');
    }

    public function testGetPublic()
    {
        $publicKey = <<<TEXT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs4Py96JkdXjt8ZZHIopd
DkMDS+n+B1D9G0Cli5Gnd9uE+EUvKLlHJHRKohvcccnpAnDbbUtN2UD7/fVem6Wq
CbrNRR3gtBzf5+TlQnCc/lo7EaNBOvhX39vGYZscwGlVv3wyzTe/AKz98OQBjb5J
8HqH6vS9bqgsSLGBdfTLoAkv5XhtoyuTB3PwlhKcasP+ITbkFvYvfUmUcUEORkjI
hxz3AThiXscepHD2BWHKhNJjcO/HT/6SapaPYTvJRZWvebULNE3wI9q0dxNT3ZZS
dFQoEDpFOEjm+GRugO/g/7RdC+asT+NMUHdkn/xa8e52eHnmFcXxEFBh+iTApFqh
5wIDAQAB
-----END PUBLIC KEY-----
TEXT;

        $pkey = PKey::getPublic($publicKey);

        $this->assertInstanceOf(PKey::class, $pkey);

        $publicKey = $pkey->getPublicKey();

        $pkey->free();

        $this->assertEquals('-----BEGIN PUBLIC KEY-----', substr($publicKey, 0, 26));
    }

    public function testGetPublicInvalidFormat()
    {
        $this->expectException(Exception::class);

        $publicKey = <<<TEXT
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs4Py96JkdXjt8ZZHIopd
DkMDS+n+B1D9G0Cli5Gnd9uE+EUvKLlHJHRKohvcccnpAnDbbUtN2UD7/fVem6Wq
CbrNRR3gtBzf5+TlQnCc/lo7EaNBOvhX39vGYZscwGlVv3wyzTe/AKz98OQBjb5J
8HqH6vS9bqgsSLGBdfTLoAkv5XhtoyuTB3PwlhKcasP+ITbkFvYvfUmUcUEORkjI
hxz3AThiXscepHD2BWHKhNJjcO/HT/6SapaPYTvJRZWvebULNE3wI9q0dxNT3ZZS
dFQoEDpFOEjm+GRugO/g/8RdC+asT+NMUHdkn/xa8e52eHnmFcXxEFBh+iTApFqh
5wIDAQAB
-----END PUBLIC KEY-----
TEXT;

        PKey::getPublic($publicKey);
    }
}
