package com.sonar.zap;

import com.sonar.zap.scanner.ZapSensor;
import com.sonar.zap.web.ZapPageDefinition;
import org.sonar.api.Plugin;
import org.sonar.api.PropertyType;
import org.sonar.api.config.PropertyDefinition;
import org.sonar.api.resources.Qualifiers;

public class ZapPlugin implements Plugin {

  private static final String CATEGORY = "OWASP ZAP";

  @Override
  public void define(Context context) {
    context.addExtensions(
      ZapSensor.class,
      ZapMetrics.class,
      ZapPageDefinition.class,
      PropertyDefinition.builder(ZapConstants.REPORT_PATHS_KEY)
        .name("ZAP report paths")
        .description("Comma-separated paths to ZAP reports (.json or .xml), relative to the project base directory. "
          + "A wildcard (*) is allowed in the file name.")
        .category(CATEGORY)
        .onQualifiers(Qualifiers.PROJECT)
        .multiValues(true)
        .build(),
      PropertyDefinition.builder(ZapConstants.HTML_REPORT_PATH_KEY)
        .name("ZAP HTML report path")
        .description("Path to the ZAP HTML report to display on the project's ZAP page.")
        .category(CATEGORY)
        .onQualifiers(Qualifiers.PROJECT)
        .build(),
      PropertyDefinition.builder(ZapConstants.SKIP_KEY)
        .name("Skip ZAP import")
        .description("Set to true to skip the ZAP report import.")
        .category(CATEGORY)
        .type(PropertyType.BOOLEAN)
        .defaultValue("false")
        .onQualifiers(Qualifiers.PROJECT)
        .build());
  }
}
