package com.sonar.zap.scanner;

import static org.assertj.core.api.Assertions.assertThat;

import com.sonar.zap.ZapConstants;
import com.sonar.zap.ZapMetrics;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.sonar.api.batch.rule.Severity;
import org.sonar.api.batch.sensor.issue.ExternalIssue;
import org.sonar.api.batch.sensor.internal.SensorContextTester;

class ZapSensorTest {

  @TempDir
  Path baseDir;

  SensorContextTester context;

  @BeforeEach
  void setUp() throws Exception {
    context = SensorContextTester.create(baseDir);
    Files.copy(Path.of(getClass().getResource("/reports/zap.json").toURI()), baseDir.resolve("zap.json"));
    Files.copy(Path.of(getClass().getResource("/reports/zap.xml").toURI()), baseDir.resolve("zap.xml"));
  }

  @Test
  void importsExternalIssuesAndMetrics() {
    context.settings().setProperty(ZapConstants.REPORT_PATHS_KEY, "zap.json");

    new ZapSensor().execute(context);

    // 2 CSP instances + 1 XSS + 1 alert without instances
    assertThat(context.allExternalIssues()).hasSize(4);
    ExternalIssue xss = context.allExternalIssues().stream().filter(i -> i.ruleId().equals("40012")).findFirst().orElseThrow();
    assertThat(xss.engineId()).isEqualTo("zap");
    assertThat(xss.severity()).isEqualTo(Severity.CRITICAL);
    assertThat(xss.primaryLocation().message()).contains("GET http://localhost:8080/search").contains("param: q");

    assertThat(context.allAdHocRules()).extracting(r -> r.ruleId()).containsExactlyInAnyOrder("10038", "40012", "10015");

    String projectKey = context.project().key();
    assertThat(context.measure(projectKey, ZapMetrics.HIGH_RISK_ALERTS).value()).isEqualTo(1);
    assertThat(context.measure(projectKey, ZapMetrics.MEDIUM_RISK_ALERTS).value()).isEqualTo(2);
    assertThat(context.measure(projectKey, ZapMetrics.INFO_RISK_ALERTS).value()).isEqualTo(1);
    assertThat(context.measure(projectKey, ZapMetrics.TOTAL_ALERTS).value()).isEqualTo(4);
    assertThat(context.measure(projectKey, ZapMetrics.RISK_SCORE).value()).isEqualTo(5 + 3 * 2);
  }

  @Test
  void deduplicatesAcrossReportsAndSupportsWildcards() {
    context.settings().setProperty(ZapConstants.REPORT_PATHS_KEY, "zap.json,zap.*");

    new ZapSensor().execute(context);

    // the XSS instance appears in both formats but is imported once
    assertThat(context.allExternalIssues()).filteredOn(i -> i.ruleId().equals("40012")).hasSize(1);
  }

  @Test
  void storesHtmlReport() throws Exception {
    Files.writeString(baseDir.resolve("zap.html"), "<html>report</html>");
    context.settings().setProperty(ZapConstants.HTML_REPORT_PATH_KEY, "zap.html");

    new ZapSensor().execute(context);

    assertThat(context.measure(context.project().key(), ZapMetrics.HTML_REPORT).value()).isEqualTo("<html>report</html>");
    assertThat(context.allExternalIssues()).isEmpty();
  }

  @Test
  void skipsWhenConfigured() {
    context.settings().setProperty(ZapConstants.REPORT_PATHS_KEY, "zap.json");
    context.settings().setProperty(ZapConstants.SKIP_KEY, "true");

    new ZapSensor().execute(context);

    assertThat(context.allExternalIssues()).isEmpty();
  }

  @Test
  void toleratesMissingAndBrokenReports() throws Exception {
    Files.writeString(baseDir.resolve("broken.json"), "{not json");
    context.settings().setProperty(ZapConstants.REPORT_PATHS_KEY, "missing.json,broken.json");

    new ZapSensor().execute(context);

    assertThat(context.allExternalIssues()).isEmpty();
  }
}
