package com.sonar.zap.report;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

public interface ZapReportParser {

  ZapReport parse(InputStream in) throws IOException;

  /** Picks the JSON or XML parser from the file extension. */
  static ZapReport parse(Path file) throws IOException {
    String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
    ZapReportParser parser;
    if (name.endsWith(".json")) {
      parser = new JsonZapReportParser();
    } else if (name.endsWith(".xml")) {
      parser = new XmlZapReportParser();
    } else {
      throw new IOException("Unsupported ZAP report extension (expected .json or .xml): " + file);
    }
    try (InputStream in = Files.newInputStream(file)) {
      return parser.parse(in);
    }
  }
}
