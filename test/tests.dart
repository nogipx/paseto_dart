import 'package:paseto_dart/paseto_dart.dart';
import 'vector_test.dart';
import 'vectors.dart';

/// Тесты PASETO v4, основанные только на официальных тестовых векторах
void main() {
  final vectorsV4 = Vectors.fromJsonFile(Version.v4, 'test/vectors/v4.json');
  localTest(vectorsV4);
  // publicTest(vectorsV4);

  // final vectorsV3 = Vectors.fromJsonFile(Version.v3, 'test/vectors/v3.json');
  // localTest(vectorsV3);
  // publicTest(vectorsV3);
}
