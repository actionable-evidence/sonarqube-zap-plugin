package com.sonar.zap;

import java.util.List;
import org.sonar.api.measures.Metric;
import org.sonar.api.measures.Metrics;

public class ZapMetrics implements Metrics {

  private static final String DOMAIN = "OWASP ZAP";

  public static final Metric<Integer> HIGH_RISK_ALERTS = intMetric("zap_high_risk_alerts", "High Risk Alerts");
  public static final Metric<Integer> MEDIUM_RISK_ALERTS = intMetric("zap_medium_risk_alerts", "Medium Risk Alerts");
  public static final Metric<Integer> LOW_RISK_ALERTS = intMetric("zap_low_risk_alerts", "Low Risk Alerts");
  public static final Metric<Integer> INFO_RISK_ALERTS = intMetric("zap_info_risk_alerts", "Informational Alerts");
  public static final Metric<Integer> TOTAL_ALERTS = intMetric("zap_total_alerts", "Total ZAP Alerts");

  public static final Metric<Integer> RISK_SCORE = new Metric.Builder("zap_risk_score", "ZAP Risk Score", Metric.ValueType.INT)
    .setDescription("High x 5 + Medium x 3 + Low x 1")
    .setDirection(Metric.DIRECTION_WORST)
    .setQualitative(false)
    .setDomain(DOMAIN)
    .setBestValue(0.0)
    .create();

  public static final Metric<String> HTML_REPORT = new Metric.Builder("zap_html_report", "ZAP HTML Report", Metric.ValueType.DATA)
    .setDescription("OWASP ZAP HTML report")
    .setQualitative(false)
    .setDomain(DOMAIN)
    .setDeleteHistoricalData(true)
    .create();

  private static Metric<Integer> intMetric(String key, String name) {
    return new Metric.Builder(key, name, Metric.ValueType.INT)
      .setDescription(name)
      .setDirection(Metric.DIRECTION_WORST)
      .setQualitative(false)
      .setDomain(DOMAIN)
      .setBestValue(0.0)
      .create();
  }

  @Override
  public List<Metric> getMetrics() {
    return List.of(HIGH_RISK_ALERTS, MEDIUM_RISK_ALERTS, LOW_RISK_ALERTS, INFO_RISK_ALERTS, TOTAL_ALERTS, RISK_SCORE, HTML_REPORT);
  }
}
