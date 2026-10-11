package com.sonar.zap.scanner;

import com.sonar.zap.ZapConstants;
import com.sonar.zap.ZapMetrics;
import com.sonar.zap.report.ZapReport;
import com.sonar.zap.report.ZapReport.Alert;
import com.sonar.zap.report.ZapReport.Instance;
import com.sonar.zap.report.ZapReport.Site;
import com.sonar.zap.report.ZapReportParser;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.sensor.Sensor;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.SensorDescriptor;
import org.sonar.api.batch.sensor.issue.NewExternalIssue;
import org.sonar.api.batch.sensor.issue.NewIssueLocation;
import org.sonar.api.measures.Metric;

/** Imports ZAP reports as external issues and stores summary metrics and the HTML report. */
public class ZapSensor implements Sensor {

  private static final Logger LOG = LoggerFactory.getLogger(ZapSensor.class);

  @Override
  public void describe(SensorDescriptor descriptor) {
    descriptor.name("OWASP ZAP").global();
  }

  @Override
  public void execute(SensorContext context) {
    if (context.config().getBoolean(ZapConstants.SKIP_KEY).orElse(false)) {
      LOG.info("ZAP import skipped ({}=true)", ZapConstants.SKIP_KEY);
      return;
    }
    Path baseDir = context.fileSystem().baseDir().toPath();
    List<Path> reports = resolveReports(baseDir, context.config().getStringArray(ZapConstants.REPORT_PATHS_KEY));
    if (!reports.isEmpty()) {
      importReports(context, reports);
    }
    context.config().get(ZapConstants.HTML_REPORT_PATH_KEY).ifPresentOrElse(
      p -> saveHtmlReport(context, baseDir.resolve(p)),
      () -> LOG.info("{} is not set, the ZAP HTML report page will be empty", ZapConstants.HTML_REPORT_PATH_KEY));
  }

  private static void importReports(SensorContext context, List<Path> reports) {
    Set<String> seenRules = new HashSet<>();
    Set<String> seenIssues = new HashSet<>();
    int[] counts = new int[4]; // index = riskcode 0..3

    for (Path path : reports) {
      ZapReport report;
      try {
        report = ZapReportParser.parse(path);
      } catch (IOException | RuntimeException e) {
        LOG.warn("Cannot read ZAP report {}: {}", path, e.getMessage());
        continue;
      }
      LOG.info("Importing {} ZAP alert(s) from {}", report.alertCount(), path);
      for (Site site : report.sites()) {
        for (Alert alert : site.alerts()) {
          if (alert.ruleId().isEmpty()) {
            LOG.debug("Skipping ZAP alert without plugin id: {}", alert.name());
            continue;
          }
          if (seenRules.add(alert.ruleId())) {
            saveRule(context, alert);
          }
          List<Instance> instances = alert.instances().isEmpty() ? java.util.Collections.singletonList(null) : alert.instances();
          for (Instance instance : instances) {
            if (seenIssues.add(ZapIssueMapper.dedupeKey(alert, instance))) {
              saveIssue(context, alert, instance);
              counts[Math.max(0, Math.min(3, alert.riskCode()))]++;
            }
          }
        }
      }
    }
    saveMetrics(context, counts);
  }

  private static void saveRule(SensorContext context, Alert alert) {
    context.newAdHocRule()
      .engineId(ZapConstants.ENGINE_ID)
      .ruleId(alert.ruleId())
      .name(ZapIssueMapper.ruleName(alert))
      .description(ZapIssueMapper.ruleDescription(alert))
      .type(ZapIssueMapper.ruleType())
      .cleanCodeAttribute(ZapIssueMapper.cleanCodeAttribute())
      .severity(ZapIssueMapper.severity(alert.riskCode()))
      .addDefaultImpact(ZapIssueMapper.quality(), ZapIssueMapper.impact(alert.riskCode()))
      .save();
  }

  private static void saveIssue(SensorContext context, Alert alert, Instance instance) {
    NewExternalIssue issue = context.newExternalIssue();
    NewIssueLocation location = issue.newLocation()
      .on(context.project())
      .message(ZapIssueMapper.message(alert, instance));
    issue.engineId(ZapConstants.ENGINE_ID)
      .ruleId(alert.ruleId())
      .type(ZapIssueMapper.ruleType())
      .cleanCodeAttribute(ZapIssueMapper.cleanCodeAttribute())
      .severity(ZapIssueMapper.severity(alert.riskCode()))
      .addImpact(ZapIssueMapper.quality(), ZapIssueMapper.impact(alert.riskCode()))
      .at(location)
      .save();
  }

  private static void saveMetrics(SensorContext context, int[] counts) {
    int high = counts[3];
    int medium = counts[2];
    int low = counts[1];
    int info = counts[0];
    saveInt(context, ZapMetrics.HIGH_RISK_ALERTS, high);
    saveInt(context, ZapMetrics.MEDIUM_RISK_ALERTS, medium);
    saveInt(context, ZapMetrics.LOW_RISK_ALERTS, low);
    saveInt(context, ZapMetrics.INFO_RISK_ALERTS, info);
    saveInt(context, ZapMetrics.TOTAL_ALERTS, high + medium + low + info);
    saveInt(context, ZapMetrics.RISK_SCORE, high * 5 + medium * 3 + low);
  }

  private static void saveInt(SensorContext context, Metric<Integer> metric, int value) {
    context.<Integer>newMeasure().forMetric(metric).on(context.project()).withValue(value).save();
  }

  private static void saveHtmlReport(SensorContext context, Path html) {
    try {
      if (!Files.isRegularFile(html)) {
        LOG.warn("ZAP HTML report not found: {}", html);
        return;
      }
      if (Files.size(html) > ZapConstants.MAX_HTML_REPORT_BYTES) {
        LOG.warn("ZAP HTML report {} is larger than {} bytes, it is not stored", html, ZapConstants.MAX_HTML_REPORT_BYTES);
        return;
      }
      String content = Files.readString(html, StandardCharsets.UTF_8);
      context.<String>newMeasure().forMetric(ZapMetrics.HTML_REPORT).on(context.project()).withValue(content).save();
      LOG.info("Stored ZAP HTML report {} ({} bytes)", html, content.length());
    } catch (IOException e) {
      LOG.warn("Cannot read ZAP HTML report {}: {}", html, e.getMessage());
    }
  }

  /** Resolves configured paths; a wildcard is supported in the file name only. */
  static List<Path> resolveReports(Path baseDir, String[] configured) {
    List<Path> result = new ArrayList<>();
    for (String entry : configured) {
      String trimmed = entry.trim();
      if (trimmed.isEmpty()) {
        continue;
      }
      Path path = baseDir.resolve(trimmed).normalize();
      if (trimmed.contains("*")) {
        Path parent = path.getParent();
        if (parent != null && Files.isDirectory(parent)) {
          try (DirectoryStream<Path> stream = Files.newDirectoryStream(parent, path.getFileName().toString())) {
            stream.forEach(result::add);
          } catch (IOException e) {
            LOG.warn("Cannot list ZAP reports matching {}: {}", trimmed, e.getMessage());
          }
        }
      } else if (Files.isRegularFile(path)) {
        result.add(path);
      } else {
        LOG.warn("ZAP report not found: {}", path);
      }
    }
    return result;
  }
}
