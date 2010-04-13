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
        'src/crypto/md5/md5.cc',
        'src/crypto/prf/prf.cc',
        'src/crypto/rc4/rc4.cc',
        'src/crypto/sha1/sha1.cc',
      ],
    },

    {
      'target_name': 'libtlsclient_unittests',
      'type': 'executable',
      'include_dirs': [
        '..',
      ],
      'sources': [
        'tests/arena_unittest.cc',
        'tests/buffer_unittest.cc',
        'tests/connection_unittest.cc',
        'tests/error_unittest.cc',
        'tests/handshake_unittest.cc',
        'tests/hmac_unittest.cc',
        'tests/md5_unittest.cc',
        'tests/openssl-context.cc',
        'tests/prf_unittest.cc',
        'tests/rc4_unittest.cc',
        'tests/sha1_unittest.cc',
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
        '-lcrypto',
      ],
      # 'defines': ['GTEST_USE_OWN_TR1_TUPLE=1'],
    },

    {
      'target_name': 'openssl-helper',
      'type': 'executable',
      'sources': [
        'tests/openssl-helper.cc',
      ],
      'cflags': [
        '-I/home/agl/devel/openssl-0.9.8m/include',
      ],
      'ldflags': [
        '-L/home/agl/devel/openssl-0.9.8m',
        '-lcrypto',
        '-lssl',
      ],
    },
  ],
}
