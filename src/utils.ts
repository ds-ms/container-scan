import * as fs from 'fs';
import * as core from '@actions/core';
import * as dockleHelper from './dockleHelper';
import * as gitHubHelper from './gitHubHelper';
import * as inputHelper from './inputHelper';
import * as trivyHelper from './trivyHelper';
import * as fileHelper from './fileHelper';
import { GitHubClient } from './githubClient';
import { StatusCodes } from "./httpClient";
import { run } from './main';

const APP_NAME = 'Scanitizer';
const APP_LINK = 'https://github.com/apps/scanitizer';

export async function createScanResult(trivyStatus: number, dockleStatus: number): Promise<void> {
  const gitHubClient = new GitHubClient(process.env.GITHUB_REPOSITORY, inputHelper.githubToken);
  const scanResultPayload = getScanResultPayload(trivyStatus, dockleStatus);
  const response = await gitHubClient.createScanResult(scanResultPayload);

  if (response.statusCode == StatusCodes.UNPROCESSABLE_ENTITY
    && response.body
    && response.body.message
    && response.body.message.error_code === 'APP_NOT_INSTALLED') {
    // If the app is not installed, try to create the check run using GitHub actions token.
    console.log('Looks like the scanitizer app is not installed on the repo. Falling back to check run creation through GitHub actions app...');
    console.log(`For a better experience with managing allowedlist, install ${APP_NAME} app from ${APP_LINK}.`);

    const checkRunPayload = getCheckRunPayload(trivyStatus, dockleStatus);
    await gitHubClient.createCheckRun(checkRunPayload);
  }
  else if (response.statusCode != StatusCodes.OK) {
    throw Error(`An error occured while creating scan result. Statuscode: ${response.statusCode}, StatusMessage: ${response.statusMessage}, head_sha: ${scanResultPayload['head_sha']}`);
  }
  else {
    console.log(`Created scan result. Url: ${response.body['check_run']['html_url']}`);
  }
}

export function getScanReport(trivyStatus: number, dockleStatus: number): string {
  const scanReportPath = `${fileHelper.getContainerScanDirectory()}/scanreport.json`;
  let trivyOutput = [];
  if (trivyStatus === trivyHelper.TRIVY_EXIT_CODE)
    trivyOutput = trivyHelper.getFilteredOutput();
  let dockleOutput = [];
  if (inputHelper.isRunQualityChecksEnabled() && dockleStatus === dockleHelper.DOCKLE_EXIT_CODE)
    dockleOutput = dockleHelper.getFilteredOutput();
  const scanReportObject = {
    "vulnerabilities": trivyOutput,
    "bestPracticeViolations": dockleOutput
  };
  fs.writeFileSync(scanReportPath, JSON.stringify(scanReportObject, null, 2));

  return scanReportPath;
}

export function getConfigForTable(widths: number[]): any {
  let config = {
    columns: {
      0: {
        width: widths[0],
        wrapWord: true
      },
      1: {
        width: widths[1],
        wrapWord: true
      },
      2: {
        width: widths[2],
        wrapWord: true
      },
      3: {
        width: widths[3],
        wrapWord: true
      }
    }
  };

  return config;
}

export function extractErrorsFromLogs(outputPath: string, toolName?: string): any {
  const out = fs.readFileSync(outputPath, 'utf8');
  const lines = out.split('\n');
  let errors = [];
  lines.forEach((line) => {
    const errIndex = line.indexOf("FATAL");
    if (errIndex >= 0) {
      const err = line.substring(errIndex);
      errors.push(err);
    }
  });
  return errors;
}

export function addLogsToDebug(outputPath: string) {
  const out = fs.readFileSync(outputPath, 'utf8');
  core.debug(out);
}

function getCheckRunPayload(trivyStatus: number, dockleStatus: number): any {
  const headSha = gitHubHelper.getHeadSha();
  const checkConclusion = getCheckConclusion(trivyStatus, dockleStatus);
  let checkSummary = getCheckSummary(trivyStatus, dockleStatus);

  let appHyperlink = `<a href=${APP_LINK}>${APP_NAME}</a>`;
  checkSummary = `${checkSummary}\n\nFor a better experience with managing allowedlist, install ${appHyperlink} app.`

  const checkText = getCheckText(trivyStatus, dockleStatus);

  const payload = {
    head_sha: headSha,
    name: `[container-scan] ${inputHelper.imageName}`,
    status: "completed",
    conclusion: checkConclusion,
    output: {
      title: "Container scan result",
      summary: checkSummary,
      text: checkText
    }
  }

  return payload;
}

function createSarifFile(checkSummary: string, checkConclusion: string) {
  const run_number = process.env["GITHUB_RUN_ID"];
  var contents = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [
      {
        "tool": {
          "driver": {
            "name": "Azure-Container-Scan",
            "organization": "Azure",
            "version": "0.0.1",
            "rules": [
              {
                "id": `azure-container-scan-report-${run_number}`,
                "name": "Azure Container Scan",
                "shortDescription": {
                  "text": `Azure Container scan report for ${run_number}`
                },
                "fullDescription": {
                  "text": "Docker Scan results"
                },
                "defaultConfiguration": {
                  "level": "error"
                },
                "properties": {
                  "tags": [
                    "security"
                  ],
                  "kind": "problem",
                  "precision": "high",
                  "name": `Azure Container Scan report - ${run_number}`,
                  "description": "These are the results from your azure/container-scan@v0",
                  "id": `azure-container-scan-report-${run_number}`,
                  "problem.severity": "recommendation"
                },
                "help": {
                  "text": checkConclusion
                }
              }
            ]
          }
        },
        "results": [
          {
            "ruleId": `azure-container-scan-report-${run_number}`,
            "ruleIndex": 0,
            "message": {
              "text": checkSummary
            },
            "locations": [
              {
                "physicalLocation": {
                  "artifactLocation": {
                    "uri": "Dockerfile",
                    "uriBaseId": "%SRCROOT%",
                    "index": 0
                  },
                  "region": {
                    "startLine": 1,
                    "startColumn": 1,
                    "endColumn": 2
                  }
                }
              }
            ]
          }
        ],
        "columnKind": "utf16CodeUnits",
        "properties": {
          "semmle.formatSpecifier": "2.1.0",
          "semmle.sourceLanguage": "java"
        }
      }
    ]
  };

  const scanReportPath = `${fileHelper.getContainerScanDirectory()}/scanreport.sarif`;
  fs.writeFileSync(scanReportPath, JSON.stringify(contents, null, 2));
  core.setOutput('sarif-file-path', scanReportPath);
  return scanReportPath;
}

function getScanResultPayload(trivyStatus: number, dockleStatus: number): any {
  const headSha = gitHubHelper.getHeadSha();
  const checkConclusion = getCheckConclusion(trivyStatus, dockleStatus);
  const checkSummary = getCheckSummary(trivyStatus, dockleStatus);

  const checkText = getCheckText(trivyStatus, dockleStatus);

  createSarifFile(checkSummary, checkText);
  const payload = {
    action_name: process.env['GITHUB_ACTION'],
    action_sha: process.env['GITHUB_ACTION'],
    additional_properties: {
      conclusion: checkConclusion,
      is_pull_request: gitHubHelper.isPullRequestTrigger()
    },
    description: checkText,
    head_sha: headSha,
    image_name: inputHelper.imageName,
    status: "completed",
    summary: checkSummary
  }

  return payload;
}

function getCheckConclusion(trivyStatus: number, dockleStatus: number): string {
  const checkConclusion = trivyStatus != 0 ? 'failure' : 'success';
  return checkConclusion;
}

function getCheckSummary(trivyStatus: number, dockleStatus: number): string {
  const header: string = `Scanned image \`${inputHelper.imageName}\`.\nSummary:`;
  const trivySummary = trivyHelper.getSummary(trivyStatus);
  let summary = `${header}\n\n${trivySummary}`;

  if (inputHelper.isRunQualityChecksEnabled()) {
    const dockleSummary = dockleHelper.getSummary(dockleStatus);
    summary = `${summary}\n\n${dockleSummary}`;
  }

  return summary;
}

function getCheckText(trivyStatus: number, dockleStatus: number): string {
  const separator = '___';
  const trivyText = trivyHelper.getText(trivyStatus);
  let text = trivyText;

  if (inputHelper.isRunQualityChecksEnabled()) {
    const dockleText = dockleHelper.getText(dockleStatus);
    text = `${text}\n${separator}\n${dockleText}`;
  }

  let allowedlistFilePath = `${process.env['GITHUB_WORKSPACE']}/.github/containerscan/allowedlist.yaml`;
  let exists = true;
  let extension = "";
  if (!fs.existsSync(allowedlistFilePath)) {
    allowedlistFilePath = `${process.env['GITHUB_WORKSPACE']}/.github/containerscan/allowedlist.yml`;
    if (!fs.existsSync(allowedlistFilePath)) {
      exists = false;
    }
    else {
      extension = ".yml"
    }
  }
  else {
    extension = ".yaml";
  }

  if (exists) {
    const commit = process.env["GITHUB_SHA"];
    text = `The exempted vulnerabilities can be found here: https://github.com/${process.env['GITHUB_REPOSITORY']}/blob/${commit}/.github/containerscan/allowedlist.${extension}
    ${text}`
  }

  return text;
}
