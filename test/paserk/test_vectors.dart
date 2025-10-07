/// Official PASERK v4 test vectors from https://github.com/paseto-standard/test-vectors
const Map<String, Map<String, Object>> k4TestVectors = {
  'k4.local': {
    'name': 'k4.local-2',
    'key': '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f',
    'paserk': 'k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
  },
  'k4.secret': {
    'name': 'k4.secret-2',
    'secret':
        '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35',
    'paserk':
        'k4.secret.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8c5WpIyC_5kWKhS8VEYSZ05dYfuTF-ZdQFV4D9vLTcNQ',
  },
  'k4.public': {
    'name': 'k4.public derived from secret-2',
    'public':
        '1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35',
    'paserk': 'k4.public.HOVqSMgv-ZFioUvFRGEmdOXWH7kxfmXUBVeA_by03DU',
  },
  'k4.local-wrap': {
    'name': 'k4.local-wrap.pie-2',
    'unwrapped':
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'wrapping':
        '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f',
    'paserk':
        'k4.local-wrap.pie.cy-Mu6zSfhu6q0_XdAM9p1zre_joUWjreSjHgisVNh-oHaNarN4_c7xuSyaHwqEDxF7lTbfNplBGU7wTeUyt__hZyj1J38NdNxVwuXamJY2QhRE-kWYA9_16xTsGwCQX',
  },
  'k4.secret-wrap': {
    'name': 'k4.secret-wrap.pie-2',
    'unwrapped':
        '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35',
    'wrapping':
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'paserk':
        'k4.secret-wrap.pie.dYA31PP6a-d1Cyk3xt2Dz8kpGSlbpwkG5UyrLcgRspSvq1RUO1UQicQNE3-eXYUYGhXrG9zAVnR93tize-IPtiFEyO70U3bWEXd0uU7asDJQ19I3V2mf5OPIcKQl-TnY0XXtw5DPqY1yEFEbA9WTiDG0I3z6KTWA2z09NWm0OHQ',
  },
  'k4.local-pw': {
    'name': 'k4.local-pw-1',
    'unwrapped':
        '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f',
    'passwordHex': '636f727265637420686f727365206261747465727920737461706c65',
    'memlimit': 67108864,
    'opslimit': 2,
    'paserk':
        'k4.local-pw.9VvzoqE_i23NOqsP9xoijQAAAAAEAAAAAAAAAgAAAAG_uxDZC-NsYyOW8OUOqISJqgHN8xIfAXiPfmFTfB4GPidUzm4aKzMGJmZtRPeyZCV11MxEJS3VMIRHXxYsfUQsmWLALpFwqUhxZdk_ymFcK2Nk0-N7CVp-',
  },
  'k4.secret-pw': {
    'name': 'k4.secret-pw-1',
    'unwrapped':
        '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f1ce56a48c82ff99162a14bc544612674e5d61fb9317e65d4055780fdbcb4dc35',
    'passwordHex': '636f727265637420686f727365206261747465727920737461706c65',
    'memlimit': 67108864,
    'opslimit': 2,
    'paserk':
        'k4.secret-pw.g5CZn27bLJQkPVOYjrWEQAAAAAAEAAAAAAAAAgAAAAGpohE13nAyCtWfj2Xf3rgORRrE1X0qw2U1FWSJm_6snSbneAqz59FTgsmUR2cNmC41rauCVViAEijox_mY4iJzIUOv34cHkLLIZ_te-FpqKDK0bFtH-rgdFkiy-RjCG0EN349NFFqCZHu7gOlQw98nyeRwWelHCJE',
  },
  'k4.seal': {
    'name': 'k4.seal-1',
    'localKey':
        '0000000000000000000000000000000000000000000000000000000000000000',
    'public':
        'b7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023',
    'secret':
        '407796f4bc4b8184e9fe0c54b336822d34823092ad873d87ba14c3efb9db8c1db7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023',
    'paserk':
        'k4.seal.OPFn-AEUsKUWtAUZrutVvd9YaZ4CmV4_lk6ii8N72l5gTnl8RlL_zRFqWTZZV9gSnPzARQ_QklrZ2Qs6cJGKOENNOnsDXL5haXcr-QbTXgoLVBvT4ruJ8MdjWXGRTVc9',
  },
  'k4.lid': {
    'name': 'k4.lid-1',
    'key': 'k4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    'paserk': 'k4.lid.bqltbNc4JLUAmc9Xtpok-fBuI0dQN5_m3CD9W_nbh559',
  },
  'k4.pid': {
    'name': 'k4.pid-1',
    'key': 'k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    'paserk': 'k4.pid.S_XQmeEwHbbvRmiyfXfHYpLGjXGzjTRSDoT1YtTakWFE',
  },
  'k4.sid': {
    'name': 'k4.sid-1',
    'key':
        'k4.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ',
    'paserk': 'k4.sid.YujQ-NvcGquQ0Q-arRf8iYEcXiSOKg2Vk5az-n1lxiUd',
  }
};
