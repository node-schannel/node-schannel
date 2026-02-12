{
  "targets": [
    {
      "target_name": "schannels",
      "sources": [
        "src/addon.cc",
        "src/cert_store.cc",
        "src/schannel_socket.cc",
        "src/async_workers/connect_worker.cc",
        "src/async_workers/write_worker.cc",
        "src/async_workers/read_worker.cc",
        "src/async_workers/close_worker.cc",
        "src/async_workers/list_certs_worker.cc"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS",
        "SECURITY_WIN32",
        "WIN32_LEAN_AND_MEAN"
      ],
      "conditions": [
        [
          "OS=='win'",
          {
            "libraries": [
              "-lsecur32.lib",
              "-lcrypt32.lib",
              "-lws2_32.lib"
            ]
          }
        ]
      ]
    }
  ]
}
