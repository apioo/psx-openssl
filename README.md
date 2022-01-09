
# OpenSsl

## About

Wrapper to the openssl_* functions. Each method throws directly an exception in
case an error occurred.

## Usage


### Encrypt/Decrypt

```php
<?php

$data   = 'Secret text';
$key    = 'foobar';
$method = 'aes-128-cbc';
$iv     = substr(md5('foo'), 4, 16);

$encrypt = OpenSsl::encrypt($data, $method, $key, 0, $iv);

$this->assertEquals('U1dIdXBaY25uOTRaZ3dhZ1l6QzQwZz09', base64_encode($encrypt));

$decrypt = OpenSsl::decrypt($encrypt, $method, $key, 0, $iv);

$this->assertEquals($data, $decrypt);
```

### Sign/Verify

```php
<?php

$pkey = PKey::getPrivate('private.pem', 'foobar');
$data = 'Some content';

OpenSsl::sign($data, $signature, $pkey);

$result = OpenSsl::verify($data, $signature, $pkey);

$this->assertEquals('S9zEMrH5RTYkC/iUiHCbDUP9MkrsivkN23QffRuTD7bMiWn5neP4QX+36zO3ynELWUSyQ6woqNO37y6KQK1t6Nk3Etkau9IplBFga8ZDBcfMIMdJmWKXWmWzycgAorxjglFkdUSer8vc1tvf4v05msufJKwg/E853ZVZuB//vb/idxBH/GPeguGw8jm3DVEn3tpmypJMd/pzBwAzWB7USG8TsSDyXhxPt8pO3ZGCJn3IPbXo6eMMx+7ad/6yyxxHwu60Ab2F5hOIiC0UR15OLH5X7plJFWPTobi95GrVfHHHNRli1zquTt5T8cu+v3Q6W1ZOeSPqF7o7pn2nUjantQ==', base64_encode($signature));
$this->assertEquals(1, $result);

$data = 'Some content corrupted';

$result = OpenSsl::verify($data, $signature, $pkey);

$this->assertEquals(0, $result);

```

### Digest

```php
<?php

$this->assertContains('sha256', OpenSsl::getMdMethods());

$data = OpenSsl::digest('foobar', 'sha256');

$this->assertEquals('c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2', $data);

```

