## arib-b61-stream-test

標準入力からMMT/TLVストリームを受け取ってデコードして標準出力に出力するプログラム

依存関係: libpcsclite, OpenSSLまたはLibreSSL, cmake, C++20に対応したコンパイラ

確認済み動作環境: Linux (gcc), Windows (MSVC++)

```
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### 他の実装との差異

ちゃんと`SCardBeginTransaction`する (超重要)

これがないと並行して動作させたときにタイミングが悪いとデータが化ける現象が発生するためとても重要

NTPパケット、TLV-SIパケットを破棄せず出力します。

複数のECMにも対応しています。 (おそらく運用されることはない)

カードリーダーを動かすスレッドは別で、ECMが送られるタイミングと実際に鍵が変わるタイミングは別なのでノンブロッキングで動作します。
(同期的に動作すると数百ミリ秒くらい停止する)
