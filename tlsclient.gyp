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
        'src/arena_unittest.cc',
        'src/buffer_unittest.cc',
        'src/connection_unittest.cc',
        'src/error_unittest.cc',
        'src/handshake_unittest.cc',
        'src/sink_unittest.cc',
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
        'src/openssl-helper.cc',
      ],
      'ldflags': [
        '-lcrypto',
        '-lssl',
      ],
    },
  ],
}
