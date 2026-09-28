package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/sysrqio/crafttrace/internal/audit"
	"github.com/sysrqio/crafttrace/internal/config"
	"github.com/sysrqio/crafttrace/internal/sbom"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "crafttrace",
		Short: "Local CRA readiness audit: SBOM, CVE summary, and readiness score",
		Long: `crafttrace scans software artifacts locally to produce an SBOM inventory,
match known vulnerabilities, and compute a Cyber Resilience Act (CRA) readiness score.

No telemetry. All processing stays on your machine.`,
		SilenceUsage: true,
	}
	root.AddCommand(newAuditCmd(), newVersionCmd(), newConfigCmd())
	return root
}

func newAuditCmd() *cobra.Command {
	var (
		target     string
		output     string
		outputFile string
		failOn     string
		minScore   int
		noColor    bool
		verbose    bool
	)

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Run SBOM + CVE audit against a target",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := audit.Options{
				Target:  target,
				Output:  output,
				OutputFile: outputFile,
				FailOn:  failOn,
				MinScore: minScore,
				NoColor: noColor,
				Verbose: verbose,
			}
			report, err := audit.Run(opts)
			if err != nil {
				return err
			}
			if verbose {
				fmt.Fprintf(os.Stderr, "crafttrace: scanned %d components\n", len(report.SBOM.Components))
			}
			if err := audit.WriteOutput(os.Stdout, report, output, noColor); err != nil {
				return err
			}
			if err := audit.WriteToFile(outputFile, report, output); err != nil {
				return err
			}
			if audit.PolicyViolation(report, failOn, minScore) {
				os.Exit(2)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&target, "target", "", "required: dir:<path>|file:<path>|sbom:<path>|docker:<image>")
	cmd.Flags().StringVar(&output, "output", "table", "table|json|cyclonedx-json|sarif")
	cmd.Flags().StringVar(&outputFile, "output-file", "", "write output to file")
	cmd.Flags().StringVar(&failOn, "fail-on", "critical", "critical|high|medium|low")
	cmd.Flags().IntVar(&minScore, "min-score", 0, "minimum CRA score (0-100)")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "disable ANSI colors in table output")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "log progress to stderr")
	_ = cmd.MarkFlagRequired("target")

	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(sbom.Version())
		},
	}
}

func newConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Show default config path and sample",
		RunE: func(cmd *cobra.Command, args []string) error {
			text, err := config.ShowInfo()
			if err != nil {
				return err
			}
			fmt.Print(text)
			return nil
		},
	}
}
