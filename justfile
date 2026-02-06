#!/usr/bin/env just --justfile

pubget:
    fvm dart pub get

prepare:
    fvm dart analyze
    fvm dart format -l 80 .
    reuse annotate -c "Karim \"nogipx\" Mamatkazin <nogipx@gmail.com>" -l "MIT" --skip-unrecognised -r lib

coverage:
    fvm dart test --coverage=coverage
    fvm dart pub global run coverage:format_coverage --lcov --in=coverage --out=coverage/lcov.info --report-on=lib
    genhtml coverage/lcov.info -o coverage/html
    open coverage/html/index.html

dry:
    fvm dart pub publish --dry-run

publish:
    fvm dart pub publish