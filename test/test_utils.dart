import 'dart:typed_data';

/// Преобразует строку с шестнадцатеричным представлением в Uint8List
Uint8List hexToUint8List(String hex) {
  // Убираем пробелы и приводим к нижнему регистру
  final cleanHex = hex.replaceAll(' ', '').toLowerCase();

  if (cleanHex.isEmpty) {
    return Uint8List(0);
  }

  // При необходимости дополняем нулем спереди для четной длины
  final paddedHex = cleanHex.length % 2 == 0 ? cleanHex : '0$cleanHex';

  // Создаем буфер нужного размера
  final buffer = Uint8List(paddedHex.length ~/ 2);

  // Заполняем буфер
  for (var i = 0; i < buffer.length; i++) {
    final byteString = paddedHex.substring(i * 2, i * 2 + 2);
    buffer[i] = int.parse(byteString, radix: 16);
  }

  return buffer;
}

/// Преобразует Uint8List в строку с шестнадцатеричным представлением
String uint8ListToHex(Uint8List bytes, {bool includeSpaces = false}) {
  final buffer = StringBuffer();
  for (var i = 0; i < bytes.length; i++) {
    // Добавляем пробел после каждых 2 символов, если требуется
    if (includeSpaces && i > 0) {
      buffer.write(' ');
    }
    // Преобразуем байт в его шестнадцатеричное представление
    // и дополняем нулем слева при необходимости
    buffer.write(bytes[i].toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}
