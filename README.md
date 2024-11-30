## arib-b61-stream-test

依存関係: libpcsclite, OpenSSLまたはLibreSSL, cmake

動作環境: Linux, Windows

```
cmake -B build -S .
cmake --build build
```

### 他の実装との差異

ちゃんと`SCardBeginTransaction`する (超重要)

これがないと並行して動作させたときにタイミングが悪いとデータが化ける現象が発生するためとても重要

カードリーダーを動かすスレッドは別で、ECMが送られるタイミングと実際に鍵が変わるタイミングは別なのでノンブロッキングで動作します。
(同期的に動作すると数百ミリ秒くらい停止する)
