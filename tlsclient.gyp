{
  'variables': {
  },

  'target_defaults': {
    'cflags': ['-Wall', '-g', '-Werror', '-I/home/agl/include'],
  },

  'targets': [
    {
      'target_name': 'libtlsclient',
      'type': 'static_library',
      'include_dirs': [
        '..',
      ],
      'sources': [
        'src/connection.cc',
        'src/error.cc',
        'src/extension.cc',
        'src/handshake.cc',
        'src/record.cc',
        'src/crypto/cipher_suites.cc',
        'src/crypto/fnv1a64/fnv1a64.cc',
        'src/crypto/md5/md5.cc',
        'src/crypto/prf/prf.cc',
        'src/crypto/rc4/rc4.cc',
        'src/crypto/sha1/sha1.cc',
        'src/crypto/sha256/sha256.cc',
      ],
    },

    {
      'target_name': 'basic_unittests',
      'type': 'executable',
      'include_dirs': [
        '..',
      ],
      'sources': [
        'tests/arena_unittest.cc',
        'tests/buffer_unittest.cc',
        'tests/error_unittest.cc',
        'tests/handshake_unittest.cc',
        'tests/hmac_unittest.cc',
        'tests/md5_unittest.cc',
        'tests/prf_unittest.cc',
        'tests/rc4_unittest.cc',
        'tests/sha1_unittest.cc',
        'tests/sha256_unittest.cc',
        'tests/sink_unittest.cc',
        'tests/util.cc',
      ],
      'dependencies': [
        'libtlsclient',
      ],
      'ldflags': [
        '-L/home/agl/lib',
        '-lpthread',
        '-lgtest',
        '-lgtest_main',
      ],
      # 'defines': ['GTEST_USE_OWN_TR1_TUPLE=1'],
    },

    {
      'target_name': 'connection_tests',
      'type': 'executable',
      'include_dirs': [
        '..',
        '/home/agl/devel/openssl-0.9.8m/include',
      ],
      'sources': [
        'tests/connection_unittest.cc',
        'tests/openssl-context.cc',
      ],
      'dependencies': [
        'libtlsclient',
      ],
      'ldflags': [
        '-L/home/agl/lib',
        '-L/home/agl/devel/openssl-0.9.8m',
        '-lpthread',
        '-lgtest',
        '-lgtest_main',
        '-lcrypto',
      ],
      # 'defines': ['GTEST_USE_OWN_TR1_TUPLE=1'],
    },

    {
      'target_name': 'openssl-helper',
      'type': 'executable',
      'include_dirs': [
        '/home/agl/devel/openssl-0.9.8m/include',
      ],
      'sources': [
        'tests/openssl-helper.cc',
      ],
      'ldflags': [
        '-L/home/agl/devel/openssl-0.9.8m',
        '-lcrypto',
        '-lssl',
      ],
    },

    {
      'target_name': 'gnutls-helper',
      'type': 'executable',
      'sources': [
        'tests/gnutls-helper.cc',
      ],
      'ldflags': [
        '-L/home/agl/src/gnutls-2.8.6/lib/.libs',
        '-lgnutls',
        '-lgcrypt',
      ],
    },

    {
      'target_name': 'tc-client',
      'type': 'executable',
      'sources': [
        'util/tc_client.cc',
        'tests/openssl-context.cc',
      ],
      'include_dirs': [
        '..',
        '/home/agl/devel/openssl-0.9.8m/include',
      ],
      'dependencies': [
        'libtlsclient',
      ],
      'ldflags': [
        '-L/home/agl/devel/openssl-0.9.8m',
        '-lcrypto',
      ],
    },
  ],
}
