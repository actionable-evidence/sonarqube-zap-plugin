package com.sonar.zap;

public final class ZapConstants {

  public static final String ENGINE_ID = "zap";
  public static final String REPORT_PATHS_KEY = "sonar.zap.reportPaths";
  public static final String HTML_REPORT_PATH_KEY = "sonar.zap.htmlReportPath";
  public static final String SKIP_KEY = "sonar.zap.skip";
  public static final String PAGE_KEY = "zap/report_page";
  /** HTML reports above this size are not stored as a measure. */
  public static final long MAX_HTML_REPORT_BYTES = 5L * 1024 * 1024;

  private ZapConstants() {
  }
}
