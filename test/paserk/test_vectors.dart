/// Тестовые векторы из официальной спецификации PASERK v4
const k4TestVectors = {
  'k4.local': {
    'name': 'Test Vector 4L-1',
    'key': '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f',
    'paserk': 'k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
  },
  'k4.secret': {
    'name': 'Test Vector 4S-1',
    'secret':
        'b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2',
    'paserk':
        'k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3QeuduuvAR8A_1wYE4AcfCYfhayy3VyJcEfAEFdDiCxog',
  },
  'k4.public': {
    'name': 'Test Vector 4P-1',
    'public':
        '1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2',
    'paserk': 'k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI',
  },
  'k4.local-wrap': {
    'name': 'Test Vector 4L-W-1',
    'unwrapped':
        '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f',
    'password': 'password',
    'paserk':
        'k4.local-wrap.hPRIYrF1YC4w2X9mrQGJEBYqHxYHw9r6gJgUr5c6OUwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEi_qPmyqRrh8ZQKD8GYrJWP4LZr4t-sBQ'
  },
  'k4.secret-wrap': {
    'name': 'Test Vector 4S-W-1',
    'unwrapped':
        'b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2',
    'password': 'password',
    'paserk':
        'k4.secret-wrap.PIEw_SxRCX2cQEfHQiZPXYYlJBs5Ql6lqnuVjN_JCXEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANCnsCAEU5E8k77wGFIxH9c01xGAzsTHHD9kS4qgqPcFKT4bALQxpJGM6LGOVDhPuXXD3zhBR3URxcYECZhGSsO0eg'
  },
  'k4.lid': {
    'name': 'Test Vector 4L-I-1',
    'key': 'k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    'paserk': 'k4.lid.sB6J3C0mJySH7QL-DTD2AxkTXj1CXE4UoJ5oaXy8xMI'
  },
  'k4.pid': {
    'name': 'Test Vector 4P-I-1',
    'key': 'k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI',
    'paserk': 'k4.pid.0WO2tqgj0kW0_CNDt9B2_TLxmwfmUX9tXpVEQ9jQhDk'
  },
  'k4.sid': {
    'name': 'Test Vector 4S-I-1',
    'key':
        'k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3QeuduuvAR8A_1wYE4AcfCYfhayy3VyJcEfAEFdDiCxog',
    'paserk': 'k4.sid.c3VJHOqh3E0gS6tIJz5WO8YXPRvzHPz7pRBUYe6ix24'
  }
};
