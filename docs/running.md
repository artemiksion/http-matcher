# Запуск и воспроизведение замеров

Все команды выполняются из корня проекта. Нужны Rust 1.93.0, Python 3,
`curl` и `unzip`; версии зависимостей закреплены в `Cargo.lock`.
Итоговые числа и ограничения измерений — в [README](../README.md),
подробный анализ — в [experiments.md](experiments.md).

## Подготовка данных

При готовом `data/` загрузку пропустить.

```sh
sh scripts/fetch-patterns.sh
mkdir -p data/requests
curl -fL --http1.1 https://downloads.openappsec.io/waf-comparison-project/legitimate.zip -o data/legitimate.zip
curl -fL --http1.1 https://downloads.openappsec.io/waf-comparison-project/malicious.zip -o data/malicious.zip
unzip -q data/legitimate.zip -d data/requests
unzip -q data/malicious.zip -d data/requests
cargo build --release --locked
```

`fetch-patterns.sh` скачивает закреплённую ревизию Nmap, чтобы набор правил
оставался одинаковым при повторении эксперимента.

## Короткий запуск только на выборке

```sh
target/release/http-matcher --mode fast --limit 10000 --output results/sample-matches.jsonl
```

Обрабатываются только первые 10 000 запросов; полный корпус затем автоматически
не запускается. Без `--workers` приложение выбирает число потоков поиска через
Rust `available_parallelism`. Для явного выбора добавить, например, `--workers 2`.

N означает N воркеров поиска плюс reader и writer, без привязки к ядрам.
Число воркеров не гарантирует занятость ровно N физических ядер.
Выбирайте значения под доступные ядра своего компьютера; оптимум зависит
от процессора, правил и корпуса, его нужно измерять.

Модульные тесты отдельно, без прогона корпуса:

```sh
cargo test --locked
python3 -B -m unittest discover -s scripts -p 'test_benchmark.py' -v
```

## Сравнение baseline и fast только на 100k

Эти команды запускают два измерения на одинаковой выборке и не переходят
к полному корпусу. Здесь выбран fast/8; замените `8` на нужное число воркеров.
Даже выборка может занять заметное время; запуски выполняйте последовательно.

```sh
target/release/http-matcher --mode baseline --workers 1 --limit 100000 --output /tmp/http-matcher-baseline-100k.jsonl 2> /tmp/http-matcher-baseline-100k-metrics.json
target/release/http-matcher --mode fast --workers 8 --limit 100000 --output /tmp/http-matcher-fast-100k.jsonl 2> /tmp/http-matcher-fast-100k-metrics.json
```

Проверка результатов и расчёт ускорения после измерений выполняются
[отдельным скриптом](../scripts/compare-results.py):

```sh
python3 -B scripts/compare-results.py
```

Скрипт читает файлы из двух команд выше, проверяет каждый ID, совпадение
результатов, метрик и исключённых правил, затем печатает время, throughput
и ускорение. При расхождении завершается с ошибкой. Проверка не запускает
новые измерения и не перезаписывает отчёты.

В приложенном [отчёте](../results/benchmark.json) независимая серия 100k
сохранена в `baseline_comparison_100k`: baseline и fast/1/2/4/8, параметры,
метрики, хеши и результаты проверки. Старые полные замеры сохранены отдельно
в `runs`; повторять полный корпус ради сравнения на 100k не требуется.

## Длительная серия: выборка и полный корпус

**Следующая команда запускает обе серии подряд и может занять много времени.**
Аргумент `100000` ограничивает только выборку, а не последующие полные прогоны.
Полный fast/1 на измеренном Apple M3 занял около 9,6 минуты; полные 1/2/4/8
суммарно — около 11,5 минуты, без выборки, сборки и проверки вывода.
На другом компьютере время может существенно отличаться.

```sh
sh scripts/benchmark.sh 100000 2 4 8
```

Можно указать любую комбинацию положительных чисел: `2 4 8`, `2 8` или `3 5 7`.
Повторы удаляются, запуски идут по возрастанию. Для машины с четырьмя доступными
ядрами можно выбрать `2 4`. Без списка скрипт использует фиксированные
`1 2 4 8`, а не определяет ядра автоматически.

Скрипт последовательно выполняет:

1. Однопоточный baseline на выборке и fast на той же выборке для выбранных чисел воркеров.
2. Fast на всём корпусе только для выбранных чисел воркеров.

Полный fast/1 запускается только при наличии `1` в списке. Например,
`sh scripts/benchmark.sh 100000 2 8` пропускает его, а
`sh scripts/benchmark.sh 100000 1 2 4 8` включает.
Полные результаты сравниваются по ID с первым выбранным запуском.
Без `1` ускорение относительно fast/1 и `S(N)/N` обозначаются `—` в таблице,
`null` в JSON; старые замеры автоматически не подставляются.
Ускорение на выборке считается относительно baseline.

Скрипт печатает таблицы и **перезаписывает `results/benchmark.json`**,
проверяет каждый ID и результаты по ID; временные JSONL удаляет.
Хеш отчёта исключённых правил сохраняется в каждой записи запуска,
в том числе у полного эталона для анализаторов профилей.

## Формат вывода и границы времени

JSONL: `{"request_id":42,"match":["http"],"softmatch":[]}`.
ID начинаются с нуля, порядок сохраняется; метрики выводятся в stderr.
Рядом с выводом создаётся `.skipped.jsonl` с причинами исключения правил.
Время приложения включает подготовку, нормализацию, поиск, запись и финальный
flush, без `fsync`. Сборка, загрузка и последующая проверка вывода не входят.

## Воспроизведение CPU-профилей

Нужны macOS и Instruments из Xcode. Это дополнительные длительные полные
прогоны, создающие большие trace/XML/JSONL. Для проверки вывода нужен полный
fast-запуск в текущем `results/benchmark.json`; анализаторы выбирают fast/1,
если он есть, иначе первый сохранённый полный fast. Корпус и правила должны
совпадать с эталоном. В списке цикла выберите подходящие числа воркеров.

Отдельная сборка сохраняет обычный benchmark-бинарник:

```sh
CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release --locked --offline --target-dir /tmp/http-matcher-profile-target
profile_output=results/profile-new
mkdir -p "$profile_output"
for n in 2 4 8; do
  xctrace record --template 'CPU Counters' --recording-options results/profile-rule-shards/recording-options.json \
    --output "$profile_output/processing-$n.trace" --target-stdout "$profile_output/processing-$n-process.log" \
    --launch -- /tmp/http-matcher-profile-target/release/http-matcher --mode fast --workers "$n" \
    --input "$PWD/data/requests" --output "$PWD/$profile_output/processing-$n-output.jsonl"
  xctrace export --input "$profile_output/processing-$n.trace" \
    --xpath '/trace-toc/run[@number="1"]/data/table[@schema="CounterMetricByThread"]' --output "$profile_output/processing-$n-counters.xml"
  xctrace export --input "$profile_output/processing-$n.trace" \
    --xpath '/trace-toc/run[@number="1"]/data/table[@schema="time-profile"]' --output "$profile_output/processing-$n-stacks.xml"
  python3 -B scripts/analyze-profile.py "$n" "$profile_output"
done
```

Для L1D заменить настройки на `recording-options-l1d.json`, префикс `processing-`
на `l1d-`, выгрузить таблицу `MetricTableForThread` в `l1d-N-metrics.xml`
и вызвать `python3 -B scripts/analyze-l1d-profile.py N "$profile_output"`.
Каталог должен быть новым: Instruments не перезаписывает существующий `.trace`.
Анализаторы сохраняют новые результаты в `summary.json` выбранного каталога.

Трассы и повторные JSONL приложенных измерений удалены после проверки.
Сводные результаты, методика и хеши сохранены в `results/experiments.json`;
для нового анализа исходных стеков нужна новая запись профиля.

## Состав сдачи

Передавать исходники, `Cargo.lock`, toolchain, скрипты, документацию,
небольшой пример и компактные итоговые файлы `results/`.
Каталоги `data/` и `target/` исключены из Git; при подготовке ZIP также
не включать корпус, сборки и временные профили.
