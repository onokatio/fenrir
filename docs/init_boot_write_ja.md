# init_boot の一時的な書き込み許可（実験版）

このフォークには、通常のAndroid起動ではFenrirのlocked / green表示を維持しながら、使用中のスロットの `init_boot` を書き込めるようにする実験機能を追加しました。通常起動では元のLKと同じ保護を設定します。明示的にフラグを設定した場合だけ、次の通常起動で `init_boot` を保護対象から外します。

v2では、実機の起動、`init_boot_b` だけがUFS保護対象から外れること、次の通常起動で保護が戻ることを確認しました。KernelSU-Nextの直接インストールも利用者から成功の報告がありました。

v3は、通常のAndroid起動でgreenを維持し、bootloaderとfastbootdで `unlocked: yes` が返ることを利用者が確認しました。recoveryはADB shellが使えず、プロパティの直接確認を省略しています。fastbootdのorangeは `unlocked: yes` による間接確認です。ビルドとテストは端末を操作しません。

初版では、通常起動後もフラグが `once-b` のまま残り、KernelSU-Nextの直接インストールで `sync boot failed` が発生しました。書き込み保護処理の引数はVerified Bootの色ですが、Fenrirが返すロック値 `4` と混同していたためです。v2からは元のLKと同じく、orangeを示す色の値 `2` の場合は保護処理をバイパスし、それ以外の通常起動で予約を消費します。以前の説明で根拠にしたログの `lock_state=1` は別の値で、この引数の観測値ではありません。v3の識別子は `FENRIR_INIT_BOOT_WRITE_V3` です。

## 対応するLK

Nothing Phone (2a) / Pacmanの、既存のFenrir LK `k6886v1_64_f26fec132_202511201009` のみに対応しています。注入先となるメインLKのSHA-256は次の値です。

```text
6d9417d1f2bb118ff1ea0767b3f6bab1d4cedd0f9205cec9a810d8d5d4ef0cd1
```

入力には、すでに正常起動を確認したFenrir LKのバックアップを使います。純正LKや別ビルドのLKは拒否します。通常の `Pacman` などの注入処理には変更を加えていません。この機能を追加する場合は `PacmanInitBootWrite` を指定します。

## ビルド

リポジトリのルートでPythonの依存関係をインストールし、AArch64のGNUツールチェーンをPATHに追加してください。

```sh
python3 -m pip install -r requirements.txt
make -C payload/init_boot_write
python3 injector/inject.py PacmanInitBootWrite /path/to/fenrir-lk-backup.img \
  -o /path/to/fenrir-lk-init-boot-write-experimental.img
```

Linuxの `aarch64-linux-gnu` ツールチェーンでもビルドできます。

```sh
make -C payload/init_boot_write CC=aarch64-linux-gnu-gcc \
  LD=aarch64-linux-gnu-gcc OBJCOPY=aarch64-linux-gnu-objcopy
```

ペイロードが未ビルド、容量超過、または入力LKが不一致の場合、注入処理はエラーで終了します。成功時も端末への書き込みは行いません。入力と出力には別のファイルを指定してください。

## 起動モードごとの表示

通常のAndroid起動（LKの `NORMAL_BOOT=0`）だけでlocked / greenを返します。それ以外では元のLKのロック状態取得処理を使い、実際にアンロックされていればorangeを返します。

| 起動先 | LKから伝える状態 |
| --- | --- |
| 通常のAndroid | locked / green（Fenrirの偽装を維持） |
| recovery（`RECOVERY_BOOT=2`） | 実際のロック状態。アンロック済みならunlocked / orange |
| bootloader fastboot（`FASTBOOT=99`） | 実際のロック状態。`getvar unlocked` はアンロック済みなら `yes` |
| fastbootd | recoveryに渡されたunlocked / orangeを引き継ぐ |
| その他の起動モード | 実際のロック状態に基づく表示 |

[AOSPのfastbootd仕様](https://source.android.com/docs/core/architecture/bootloader/fastbootd)では、fastbootdはrecovery経由で起動します。LKの色の保存先も更新するため、recoveryの起動引数がgreenのまま残らないようにしています。LKが渡す起動状態を切り替える機能で、Android起動後のプロパティは変更しません。

実際にロックされている場合は元のLKが指定した色を維持し、ロック状態の取得に失敗した場合はredを返します。通常起動以外の書き込み保護も、元のLKがその状態に対して行う処理に従います。通常のAndroidで使う一回限りの許可フラグは、これらの起動では消費しません。

## フラグの操作

以下は、このLKを導入した後に使うコマンドの仕様です。通常のFenrir LKやfastbootdには、このコマンドはありません。フラグの設定と取り消しは端末の `para` 内にあるLKの環境変数領域に書き込みます。

```sh
# 次回起動の予約状態を確認（読み取りのみ）
fastboot getvar fenrir-init-boot-write

# 現在選択されているスロットを、次の通常起動で一度だけ許可
fastboot oem fenrir-init-boot-write once

# 予約を取り消す
fastboot oem fenrir-init-boot-write cancel
```

`getvar` は `off`、`once-a`、`once-b` のいずれかを返します。これは次回起動の予約状態です。実際のUFS保護の状態を示す値ではありません。

通常起動時にフラグを `off` に戻し、ストレージから読み直して確認した後、記録したスロットと実際に選択されたスロットが一致していれば、対象の `init_boot` を保護対象から外します。そのAndroid起動中は書き込み可能な状態を維持し、次の通常起動では元の保護を設定します。recoveryやfastbootへの起動では予約を消費しません。

## 保護範囲と失敗時の処理

通常起動時にLKが設定する保護範囲を、GPTから取得した `init_boot_a` または `init_boot_b` の前後で分割します。反対側のスロット、LK、preloader、seccfgなどの保護範囲は元の処理に従います。

フラグの保存・読み直し、スロットの照合、GPTの取得に失敗した場合は元の保護処理を使います。UFSの保護エントリーはLUごとに最大4件なので、後続のseccfg用に1件を確保できない場合も元の範囲を保護します。分割した範囲のUFS設定に失敗した場合は、保護が不完全なままAndroidを起動しないよう、LKのassert処理を呼びます。

フラグを設定するだけでKernelSUの権限が得られるわけではありません。Androidから書き込むには、KernelSUなどによるroot権限と、正しいスロット・ビルドのイメージが別途必要です。

## 検証

```sh
python3 -m pip install unicorn==2.1.4
python3 -m unittest discover -s tests -v
```

テストではビルドしたAArch64バイナリをエミュレータで実行し、フラグの設定・取り消し・消費、スロットの照合、範囲分割、保護エントリーの上限、起動モード別のロック状態と色、エラー処理を確認します。ロック状態取得関数の元の後半も実行しますが、ストレージの読み取りやUFSなどのLK APIはモックです。実機の動作確認を代替するものではありません。

## 注入位置

解析対象のLKの仮想ベースは `0xffff000050f00000` です。次のオフセットを使用します。

| 対象 | オフセット |
| --- | --- |
| 未使用のeMMC関数に配置するペイロード | `0x6e4d0`、最大 `0x1350` バイト |
| `notify_enter_fastboot` の呼び出し | `0xe18c` |
| `set_write_protect` の呼び出し | `0xda2c` |
| 通常のパーティション範囲に対する `bio_ioctl` の呼び出し | `0x73330` |
| ロック状態の取得関数 / 復元する元の関数の後半 | `0x820ac` / `0x820bc` |
| Verified Bootの色のget / set | `0x4f2e0` / `0x4f2ec` |
| 起動モードの取得 | `0xae64` |
| LK環境変数のget / set / init | `0x31038` / `0x3110c` / `0x30d0c` |
| GPT取得 / UFS保護設定 | `0x734a8` / `0x36f30` |

実行中の状態には未使用のeMMC用BSS `0xffff0000510c1da0` を使います。main LK以外の領域、イメージサイズ、GPTは変更しません。別ビルドへの対応には再解析が必要です。
