# Запуск

Все команды выполняются из корня репозитория. Нужен Rust из
`rust-toolchain.toml`; зависимости закреплены в `Cargo.lock`.
Здесь собраны команды подготовки, сборки, проверки, benchmark и профилирования.
Описание алгоритмов и результатов — в [README](../README.md) и
[техническом отчёте](performance.md).

## Данные

Сигнатуры находятся в `data/nmap-service-probes`. При необходимости:

```sh
sh scripts/fetch-patterns.sh
```

Скачайте [Legitimate](https://downloads.openappsec.io/waf-comparison-project/legitimate.zip)
и [Malicious](https://downloads.openappsec.io/waf-comparison-project/malicious.zip)
из исходного ТЗ. Распакуйте корпуса под `data/requests/Legitimate/` и
`data/requests/Malicious/`. JSON-файлы обходятся в отсортированном порядке.
Путь правил фиксирован, путь корпуса меняется через `--input`.

## Сборка и проверки

```sh
cargo test --locked
cargo test --release --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all --check
cargo build --release --locked
```

Для работы без сети, когда зависимости уже доступны, добавьте `--offline`.
Проверки покрывают нормализацию, чтение JSON/правил, приоритеты сервисов,
эквивалентность примитивов и поиска литералов, границы частей запроса,
сравнение двух алгоритмов и использование подготовленного корпуса.

## Два алгоритма

```sh
target/release/http-matcher --mode fast --workers 8 --output results/matches.jsonl
target/release/http-matcher --mode baseline --workers 1 --output results/baseline-matches.jsonl
```

Для короткой проверки обоих режимов:

```sh
target/release/http-matcher --mode fast --workers 1 --limit 1000 --output results/fast-sanity.jsonl
target/release/http-matcher --mode baseline --workers 1 --limit 1000 --output results/baseline-sanity.jsonl
```

Эти команды создают два вывода для сравнения, но автоматически их не сравнивают.
Без `--workers` fast
использует число доступных процессору потоков; baseline всегда использует один.
Это число воркеров, а не ограничение или привязка к физическим ядрам.
Старые имена `prepared` и `prepared-baseline` являются алиасами этих двух режимов.

Один JSONL-объект содержит `request_id`, `match`, `softmatch`. Метрики выводятся
в stderr; исключённые правила — рядом с результатом в `<output>.skipped.jsonl`.
Программа проверяет, что выходные файлы не перезапишут входные данные или правила.

## Время обработки

Оба режима читают и нормализуют весь выбранный корпус до запуска измерения.
Основные поля метрик:

- `prepared.matching_seconds`: от освобождения стартового барьера до завершения
  всех воркеров. Включает распределение батчей, фильтры, проверки сигнатур,
  приоритеты/дедупликацию сервисов и помещение полных результатов в память.
- `prepared.matching_throughput_req_s`: запросов в секунду в этом интервале.
- `prepared.output_seconds`: сериализация, запись и flush после обработки.
- `preparation_seconds`: чтение/JSON, нормализация и подготовка matcher.
- `total_seconds` и `throughput_req_s`: полное время приложения и соответствующая
  скорость, включая подготовку и вывод.

Батчи содержат до 32 запросов или примерно 64 KiB. Большой запрос изолируется
в отдельный батч. Свободный воркер получает следующий батч; запросы не
рассылаются всем воркерам. RegexSet-кэши принадлежат воркерам, индексы общие.

## Benchmark и диагностика

```sh
python3 -B scripts/benchmark.py --workers 8 --diagnostics --report-dir results/reproduced
```

Выполняется один обычный full-corpus fast/8, затем отдельные диагностические
прогоны fast/1 и fast/8. Каждый вывод проверяется по полному упорядоченному
хешу baseline, числу запросов/байтов и отчёту исключённых правил.
Baseline по умолчанию берётся из `results/baseline.json`, где отмечен как
историческое измерение. Матрица 1/2/4/8 с тремя обычными запусками на вариант,
с той же настройкой сборки, что и сохранённая последняя серия:

```sh
cargo rustc --release --locked --bin http-matcher -- -C debuginfo=1
python3 -B scripts/benchmark.py --workers 1 2 4 8 --repetitions 3 --diagnostics \
  --report-dir results/reproduced
```

Диагностический запуск выполняется отдельно для каждого числа воркеров;
его время не входит в обычные медианы. Для нового измерения baseline:

```sh
python3 -B scripts/benchmark.py --workers 8 --repetitions 3 --baseline \
  --report-dir results/reproduced
```

Baseline запускается однократно; `--repetitions` задаёт число повторений fast.
Можно указать несколько значений `--workers`. Время диагностических запусков
не используется для расчёта обычного throughput. `--diagnostics` собирает
подробности также для одного воркера, чтобы интерпретировать последовательные
затраты без сложения параллельно работающих стадий.

Для сравнения очередной оптимизации сохраните текущий release-бинарник
до изменения кода и сборки нового. Например:

```sh
cp target/release/http-matcher /tmp/http-matcher-fast-before
# Изменить код и заново выполнить cargo build --release --locked.
python3 -B scripts/benchmark.py --workers 1 8 --repetitions 3 --diagnostics \
  --compare-binary /tmp/http-matcher-fast-before --report-dir results/reproduced
```

Старый и новый fast запускаются поочерёдно; порядок меняется между повторениями.
`full_summary` содержит только новый вариант, `comparison_vs_previous_fast` —
сравнение медиан. Каждый обычный и диагностический вывод проверяется по baseline.

Сохранённые результаты, на которые ссылается README:

- [docs/performance-data.json](performance-data.json): последняя полная серия
  13 октября, 12 обычных повторений, сводки диагностики и анализ 14 октября.
  Это источник итоговой таблицы README.
- [results/baseline.json](../results/baseline.json): сохранённое полное измерение
  naive baseline и эталон вывода.
- [results/benchmark.json](../results/benchmark.json): предыдущая серия fast.
  Ещё более ранние замеры находятся в `previous_fast_measurements`.
- [results/profile.json](../results/profile.json): сводка последней диагностики
  стадий и наиболее дорогих групп.
- [docs/performance.md](performance.md): объяснение методики, фильтров,
  приоритета probe, несовместимых правил и аппаратных ограничений.

Новые запуски записывают `benchmark.json` и, при `--diagnostics`,
`diagnostics/workers-N.json` в заданный `--report-dir`.
В командах выше это `results/reproduced/`; без флага каталогом служит `results/`.
`docs/performance-data.json` — сохранённый снимок, скрипт его не обновляет.

Профиль можно собрать непосредственно у приложения флагом `--diagnostics`
в режиме fast. Дополнительные таймеры влияют на скорость. Время отдельных
операций включает вытеснение потока ОС; суммы нескольких воркеров не являются
разложением настенного времени. CPU-время воркеров доступно на macOS/Linux.
Явного прогрева, сброса кэша ОС, affinity и `fsync` в benchmark нет.

## Аппаратное профилирование

Требуются macOS, Xcode/Instruments и доступ к аппаратным счётчикам.
Для воспроизведения обычных замеров с VM-мониторингом и аппаратных профилей:

```sh
cargo rustc --release --locked --bin http-matcher -- -C debuginfo=1
python3 -B scripts/benchmark.py --workers 1 2 4 8 --repetitions 3 --diagnostics \
  --resources --report-dir results/reproduced
python3 -B scripts/profile-hardware.py --report-dir results/reproduced
python3 -B scripts/profile-hardware.py --modes kernel --workers 1 8 \
  --report-dir results/reproduced
```

`--resources` собирает ресурсы процесса и VM-снимки. Для нового baseline
добавьте `--baseline` к benchmark; по умолчанию используется сохранённый.
При смене бинарника выбирайте новый `--report-dir`, чтобы не смешивать трассы.
Если зависимости уже доступны, сборку можно выполнить с `--offline`.

Анализ уже сохранённых трасс без нового прогона корпуса:

```sh
python3 -B scripts/profile-hardware.py --modes bottlenecks processing l1d kernel \
  --analyze-only --report-dir results/reproduced
```

Скрипт сохраняет raw traces, XML, метрики приложения и мониторинг VM.
`summary.json` и Markdown-сводка последней сессии собраны отдельно из этих отчётов;
команды не генерируют автоматически точную копию `docs/performance.md`.
