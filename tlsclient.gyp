{
  'variables': {
  },

  'target_defaults': {
    'cflags': ['-Wall', '-ggdb', '-Werror'],
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
        'tests/sink_unittest.cc',
      ],
      'dependencies': [
        'libtlsclient',
      ],
      'ldflags': [
        '-lgtest',
        '-lgtest_main',
      ],
    },

    {
      'target_name': 'openssl-helper',
      'type': 'executable',
      'sources': [
        'tests/openssl-helper.cc',
      ],
      'ldflags': [
        '-lcrypto',
        '-lssl',
      ],
    },
  ],
}
