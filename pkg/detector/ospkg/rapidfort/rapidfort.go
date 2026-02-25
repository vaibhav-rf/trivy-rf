package rapidfort

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

// platformFormat matches the format used in trivy-db's rapidfort vulnsrc:
// "rapidfort {baseOS} {version}"  e.g. "rapidfort ubuntu 22.04"
const platformFormat = "rapidfort %s %s"

// Scanner detects vulnerabilities for RapidFort curated images by querying
// the RapidFort advisory data that was ingested by trivy-db.
type Scanner struct {
	baseOS         string
	comparer       version.Comparer
	versionTrimmer func(string) string
	dbc            db.Operation
	logger         *log.Logger
}

// NewScanner creates a RapidFort Scanner for the given base OS type.
func NewScanner(baseOS ftypes.OSType) *Scanner {
	var comparer version.Comparer
	var versionTrimmer func(string) string

	switch baseOS {
	case ftypes.Debian:
		comparer = version.NewDEBComparer()
		versionTrimmer = version.Major // "12.0.1" → "12"
	case ftypes.Ubuntu:
		comparer = version.NewDEBComparer()
		versionTrimmer = version.Minor // "22.04.1" → "22.04"
	case ftypes.Alpine:
		comparer = version.NewAPKComparer()
		versionTrimmer = version.Minor // "3.17.2" → "3.17"
	default:
		comparer = version.NewDEBComparer()
		versionTrimmer = version.Minor
	}

	return &Scanner{
		baseOS:         strings.ToLower(string(baseOS)),
		comparer:       comparer,
		versionTrimmer: versionTrimmer,
		dbc:            db.Config{},
		logger:         log.WithPrefix("rapidfort"),
	}
}

// Detect queries the RapidFort advisory DB for vulnerabilities in the given packages.
func (s *Scanner) Detect(ctx context.Context, osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	osVer = s.versionTrimmer(osVer)
	platformName := fmt.Sprintf(platformFormat, s.baseOS, osVer)
	log.InfoContext(ctx, "Detecting RapidFort advisories...",
		log.String("platform", platformName),
		log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		srcName := pkg.SrcName
		if srcName == "" {
			srcName = pkg.Name
		}
		installedVer := utils.FormatSrcVersion(pkg)

		advisories, err := s.dbc.GetAdvisories(platformName, srcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get RapidFort advisories for %s: %w", srcName, err)
		}

		s.logger.DebugContext(ctx, "Package advisory lookup",
			log.String("pkg", srcName),
			log.String("platform", platformName),
			log.String("installed", installedVer),
			log.Int("advisories_found", len(advisories)))

		for _, adv := range advisories {
			vulnerable := s.isVulnerable(ctx, installedVer, adv)
			s.logger.DebugContext(ctx, "Advisory check",
				log.String("pkg", srcName),
				log.String("cve", adv.VulnerabilityID),
				log.String("installed", installedVer),
				log.Any("vulnerable_ranges", adv.VulnerableVersions),
				log.Any("fixed_versions", adv.PatchedVersions),
				log.Bool("is_vulnerable", vulnerable))

			if !vulnerable {
				continue
			}

			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgID:            pkg.ID,
				PkgName:          pkg.Name,
				InstalledVersion: utils.FormatVersion(pkg),
				FixedVersion:     strings.Join(adv.PatchedVersions, ", "),
				Layer:            pkg.Layer,
				PkgIdentifier:    pkg.Identifier,
				Custom:           adv.Custom,
				DataSource:       adv.DataSource,
			}

			if adv.Severity != dbTypes.SeverityUnknown {
				vuln.Vulnerability = dbTypes.Vulnerability{
					Severity: adv.Severity.String(),
				}
				vuln.SeveritySource = adv.DataSource.ID
			}

			s.logger.DebugContext(ctx, "Vulnerability detected",
				log.String("pkg", pkg.Name),
				log.String("cve", adv.VulnerabilityID),
				log.String("installed", vuln.InstalledVersion),
				log.String("fixed", vuln.FixedVersion),
				log.String("severity", vuln.Vulnerability.Severity))

			vulns = append(vulns, vuln)
		}
	}

	s.logger.DebugContext(ctx, "RapidFort scan complete",
		log.String("platform", platformName),
		log.Int("total_vulns", len(vulns)))

	return vulns, nil
}

func (s *Scanner) isVulnerable(ctx context.Context, installedVersion string, adv dbTypes.Advisory) bool {
	if len(adv.VulnerableVersions) == 0 {
		// No version constraints means all versions are considered vulnerable.
		return true
	}
	return s.checkConstraints(ctx, installedVersion, adv.VulnerableVersions)
}

func (s *Scanner) checkConstraints(ctx context.Context, installedVersion string, constraintsStr []string) bool {
	if installedVersion == "" {
		return false
	}

	for _, constraintStr := range constraintsStr {
		constraints, err := version.NewConstraints(constraintStr, s.comparer)
		if err != nil {
			s.logger.DebugContext(ctx, "Failed to parse version constraints",
				log.String("installed", installedVersion),
				log.String("constraint", constraintStr),
				log.Err(err))
			return false
		}

		satisfied, err := constraints.Check(installedVersion)
		if err != nil {
			s.logger.DebugContext(ctx, "Failed to check version constraints",
				log.String("installed", installedVersion),
				log.String("constraint", constraintStr),
				log.Err(err))
			return false
		}

		s.logger.DebugContext(ctx, "Version constraint check",
			log.String("installed", installedVersion),
			log.String("constraint", constraintStr),
			log.Bool("satisfied", satisfied))

		if satisfied {
			return true
		}
	}
	return false
}

// IsSupportedVersion always returns true.
// RapidFort provides its own curated advisories including for EOL distributions,
// so we never reject a scan based on OS version alone.
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}

// IncludesThirdParty implements driver.ThirdPartyAware.
// RapidFort curated images may include patched versions of third-party packages
// (e.g. MariaDB, Docker), so we scan them too rather than filtering them out.
func (s *Scanner) IncludesThirdParty() bool {
	return true
}
