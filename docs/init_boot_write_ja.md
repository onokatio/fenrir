# init_boot の一時的な書き込み許可（実験版）

このフォークには、Fenrirのlocked / green表示を維持しながら、使用中のスロットの `init_boot` をAndroidから書き込めるようにする実験機能を追加しました。通常は元のLKと同じ保護を設定します。明示的にフラグを設定した場合だけ、次の通常起動で `init_boot` を保護対象から外します。

修正版の実機での起動、UFS保護の設定結果、KernelSU-Nextからの書き込みは未検証です。生成したLKは実験用です。ビルドとテストは端末を操作しません。

初版では、通常起動後もフラグが `once-b` のまま残り、KernelSU-Nextの直接インストールで `sync boot failed` が発生しました。書き込み保護処理に渡される状態値と、Fenrirが表示用に返すロック値 `4` を混同していたためです。実機の起動ログで確認した状態値は `1` でした。修正版では元のLKと同じく、状態値が `2` の場合は保護処理をバイパスし、それ以外の通常起動で予約を消費する条件に改めました。ペイロードの識別子は `FENRIR_INIT_BOOT_WRITE_V2` です。

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

LKが設定する保護範囲を、GPTから取得した `init_boot_a` または `init_boot_b` の前後で分割します。反対側のスロット、LK、preloader、seccfgなどの保護範囲は元の処理に従います。ロック状態やVerified Bootの表示を変えるパッチには手を加えていません。

フラグの保存・読み直し、スロットの照合、GPTの取得に失敗した場合は元の保護処理を使います。UFSの保護エントリーはLUごとに最大4件なので、後続のseccfg用に1件を確保できない場合も元の範囲を保護します。分割した範囲のUFS設定に失敗した場合は、保護が不完全なままAndroidを起動しないよう、LKのassert処理を呼びます。

フラグを設定するだけでKernelSUの権限が得られるわけではありません。Androidから書き込むには、KernelSUなどによるroot権限と、正しいスロット・ビルドのイメージが別途必要です。

## 検証

```sh
python3 -m pip install unicorn==2.1.4
python3 -m unittest discover -s tests -v
```

テストではビルドしたAArch64バイナリをエミュレータで実行し、フラグの設定・取り消し・消費、スロットの照合、範囲分割、保護エントリーの上限、エラー処理を確認します。LKの関数とUFSはモックで置き換えています。実機の動作確認を代替するものではありません。

## 注入位置

解析対象のLKの仮想ベースは `0xffff000050f00000` です。次のオフセットを使用します。

| 対象 | オフセット |
| --- | --- |
| 未使用のeMMC関数に配置するペイロード | `0x6e4d0`、最大 `0x1350` バイト |
| `notify_enter_fastboot` の呼び出し | `0xe18c` |
| `set_write_protect` の呼び出し | `0xda2c` |
| 通常のパーティション範囲に対する `bio_ioctl` の呼び出し | `0x73330` |
| LK環境変数のget / set / init | `0x31038` / `0x3110c` / `0x30d0c` |
| GPT取得 / UFS保護設定 | `0x734a8` / `0x36f30` |

実行中の状態には未使用のeMMC用BSS `0xffff0000510c1da0` を使います。main LK以外の領域、イメージサイズ、GPTは変更しません。別ビルドへの対応には再解析が必要です。
