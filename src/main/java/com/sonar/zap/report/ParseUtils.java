package com.sonar.zap.report;

final class ParseUtils {

  private ParseUtils() {
  }

  static int toInt(String value, int defaultValue) {
    if (value == null) {
      return defaultValue;
    }
    try {
      return Integer.parseInt(value.trim());
    } catch (NumberFormatException e) {
      return defaultValue;
    }
  }

  static String nullToEmpty(String value) {
    return value == null ? "" : value;
  }
}
