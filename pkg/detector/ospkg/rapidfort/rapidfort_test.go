package rapidfort_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/rapidfort"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_Detect(t *testing.T) {
	type args struct {
		osVer string
		pkgs  []ftypes.Package
	}
	tests := []struct {
		name     string
		baseOS   ftypes.OSType
		fixtures []string
		args     args
		want     []types.DetectedVulnerability
		wantErr  string
	}{
		{
			name:   "Ubuntu: vulnerable curl, installed version is below fix",
			baseOS: ftypes.Ubuntu,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "22.04",
				pkgs: []ftypes.Package{
					{
						Name:       "curl",
						Version:    "7.81.0-1ubuntu1.13",
						SrcName:    "curl",
						SrcVersion: "7.81.0-1ubuntu1.13",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "curl",
					VulnerabilityID:  "CVE-2023-38039",
					InstalledVersion: "7.81.0-1ubuntu1.13",
					FixedVersion:     "7.81.0-1ubuntu1.14",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "ubuntu",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityMedium.String(),
					},
				},
				{
					PkgName:          "curl",
					VulnerabilityID:  "CVE-2023-38545",
					InstalledVersion: "7.81.0-1ubuntu1.13",
					FixedVersion:     "7.81.0-1ubuntu1.15",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "ubuntu",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
				},
			},
		},
		{
			name:   "Ubuntu: patched curl, installed version is at or above fix",
			baseOS: ftypes.Ubuntu,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "22.04.1", // patch trimmed to "22.04"
				pkgs: []ftypes.Package{
					{
						Name:       "curl",
						Version:    "7.81.0-1ubuntu1.15",
						SrcName:    "curl",
						SrcVersion: "7.81.0-1ubuntu1.15",
					},
				},
			},
			want: nil,
		},
		{
			name:   "Ubuntu: version not in DB returns empty",
			baseOS: ftypes.Ubuntu,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "20.04",
				pkgs: []ftypes.Package{
					{
						Name:       "curl",
						Version:    "7.68.0-1ubuntu2.0",
						SrcName:    "curl",
						SrcVersion: "7.68.0-1ubuntu2.0",
					},
				},
			},
			want: nil,
		},
		{
			name:   "Alpine: vulnerable libssl3",
			baseOS: ftypes.Alpine,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "3.18.4", // trimmed to "3.18"
				pkgs: []ftypes.Package{
					{
						Name:       "libssl3",
						Version:    "3.1.3-r0",
						SrcName:    "libssl3",
						SrcVersion: "3.1.3-r0",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "libssl3",
					VulnerabilityID:  "CVE-2023-5678",
					InstalledVersion: "3.1.3-r0",
					FixedVersion:     "3.1.4-r1",
					SeveritySource:   "rapidfort",
					DataSource: &dbTypes.DataSource{
						ID:     "rapidfort",
						BaseID: "alpine",
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
					},
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityMedium.String(),
					},
				},
			},
		},
		{
			name:   "Alpine: patched libssl3",
			baseOS: ftypes.Alpine,
			fixtures: []string{
				"testdata/fixtures/rapidfort.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer: "3.18",
				pkgs: []ftypes.Package{
					{
						Name:       "libssl3",
						Version:    "3.1.4-r1",
						SrcName:    "libssl3",
						SrcVersion: "3.1.4-r1",
					},
				},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			scanner := rapidfort.NewScanner(tt.baseOS)
			got, err := scanner.Detect(t.Context(), tt.args.osVer, nil, tt.args.pkgs)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			// Sort results for stable comparison since map iteration order is not deterministic
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestProvider(t *testing.T) {
	tests := []struct {
		name     string
		osFamily ftypes.OSType
		labels   map[string]string
		wantNil  bool
	}{
		{
			name:     "RapidFort Ubuntu image detected",
			osFamily: ftypes.Ubuntu,
			labels: map[string]string{
				"maintainer": "RapidFort Curation Team <rfcurators@rapidfort.com>",
			},
			wantNil: false,
		},
		{
			name:     "RapidFort Alpine image detected",
			osFamily: ftypes.Alpine,
			labels: map[string]string{
				"maintainer": "RapidFort Curation Team <rfcurators@rapidfort.com>",
			},
			wantNil: false,
		},
		{
			name:     "RapidFort Debian image detected",
			osFamily: ftypes.Debian,
			labels: map[string]string{
				"maintainer": "RapidFort Curation Team <rfcurators@rapidfort.com>",
			},
			wantNil: false,
		},
		{
			name:     "Non-RapidFort image: no maintainer label",
			osFamily: ftypes.Ubuntu,
			labels:   map[string]string{},
			wantNil:  true,
		},
		{
			name:     "Non-RapidFort image: different maintainer",
			osFamily: ftypes.Ubuntu,
			labels: map[string]string{
				"maintainer": "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
			},
			wantNil: true,
		},
		{
			name:     "Unsupported OS family: RapidFort label but RHEL",
			osFamily: ftypes.RedHat,
			labels: map[string]string{
				"maintainer": "RapidFort Curation Team <rfcurators@rapidfort.com>",
			},
			wantNil: true,
		},
		{
			name:     "Case-insensitive detection",
			osFamily: ftypes.Ubuntu,
			labels: map[string]string{
				"maintainer": "RAPIDFORT curation team",
			},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := rapidfort.Provider(tt.osFamily, nil, tt.labels)
			if tt.wantNil {
				assert.Nil(t, d)
			} else {
				assert.NotNil(t, d)
			}
		})
	}
}

func TestScanner_IsVulnerable(t *testing.T) {
	tests := []struct {
		name             string
		installedVersion string
		vulnerableRanges []string
		patchedVersions  []string
		want             bool
	}{
		{
			name:             "No version constraint: always vulnerable",
			installedVersion: "7.81.0-1ubuntu1.13",
			vulnerableRanges: []string{},
			want:             true,
		},
		{
			name:             "Vulnerable: below fix (introduced=0 format from pipeline)",
			installedVersion: "7.81.0-1ubuntu1.13",
			vulnerableRanges: []string{">= 0, < 7.81.0-1ubuntu1.15"},
			want:             true,
		},
		{
			name:             "Patched: at fix version",
			installedVersion: "7.81.0-1ubuntu1.15",
			vulnerableRanges: []string{">= 0, < 7.81.0-1ubuntu1.15"},
			want:             false,
		},
		{
			name:             "Patched: above fix version",
			installedVersion: "7.81.0-1ubuntu1.16",
			vulnerableRanges: []string{">= 0, < 7.81.0-1ubuntu1.15"},
			want:             false,
		},
		{
			name:             "Range constraint: specific introduced version",
			installedVersion: "7.81.0-1ubuntu1.13",
			vulnerableRanges: []string{">= 7.0.0, < 7.81.0-1ubuntu1.15"},
			want:             true,
		},
		{
			name:             "Alpine: APK version comparison",
			installedVersion: "3.1.3-r0",
			vulnerableRanges: []string{">= 0, < 3.1.4-r1"},
			want:             true,
		},
		{
			name:             "Fixed-version-first: installed equals patched, not vulnerable even if range would include it",
			installedVersion: "7.81.0-1ubuntu1.15",
			vulnerableRanges: []string{">= 0, < 7.81.0-1ubuntu1.16"},
			patchedVersions:  []string{"7.81.0-1ubuntu1.15"},
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := rapidfort.NewScanner(ftypes.Ubuntu)
			adv := dbTypes.Advisory{
				VulnerableVersions: tt.vulnerableRanges,
				PatchedVersions:    tt.patchedVersions,
			}
			result := scanner.IsVulnerable(t.Context(), tt.installedVersion, adv)
			assert.Equal(t, tt.want, result)
		})
	}
}
