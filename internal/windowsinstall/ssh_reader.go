package windowsinstall

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"github.com/BramVR/blender-box/internal/windowstarget"
)

type sshHeldFile interface {
	Stat() (fs.FileInfo, error)
	ReadAt([]byte, int64) (int, error)
	ReadDir(int) ([]fs.DirEntry, error)
	Close() error
	pin(string) (SSHPathPin, error)
	trust(string, uint32) error
}
type sshPathBackend interface {
	anchor(string) (sshHeldFile, error)
	child(sshHeldFile, string) (sshHeldFile, error)
}

// A scope retains each opened object; directory membership remains mutable.
type sshReadScope struct {
	backend sshPathBackend
	held    map[string]sshHeldFile
	order   []sshHeldFile
}

func newSSHReadScope(backend sshPathBackend) *sshReadScope {
	return &sshReadScope{backend: backend, held: map[string]sshHeldFile{}}
}
func (s *sshReadScope) Close() error {
	var first error
	for i := len(s.order) - 1; i >= 0; i-- {
		if err := s.order[i].Close(); err != nil && first == nil {
			first = err
		}
	}
	s.order = nil
	s.held = nil
	return first
}
func (s *sshReadScope) open(path string) (sshHeldFile, error) {
	if !windowstarget.ValidateWindowsPath(path) {
		return nil, fmt.Errorf("canonical fixed-local Windows path required")
	}
	if s.held == nil {
		return nil, fmt.Errorf("SSH read scope closed")
	}
	root := path[:3]
	components := append([]string{root}, strings.Split(path[3:], `\`)...)
	var parent sshHeldFile
	current := ""
	for i, component := range components {
		if i == 0 {
			current = component
		} else if i == 1 {
			current += component
		} else {
			current += `\` + component
		}
		file := s.held[current]
		if file == nil {
			if len(s.order) >= 16384 {
				return nil, fmt.Errorf("SSH handle budget exceeded")
			}
			var err error
			if i == 0 {
				file, err = s.backend.anchor(root)
			} else {
				file, err = s.backend.child(parent, component)
			}
			if err != nil {
				return nil, err
			}
			info, err := file.Stat()
			if err != nil || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !info.IsDir() && !info.Mode().IsRegular() || i < len(components)-1 && !info.IsDir() {
				file.Close()
				return nil, fmt.Errorf("SSH path contains reparse or invalid entry")
			}
			s.held[current] = file
			s.order = append(s.order, file)
		}
		parent = file
	}
	return parent, nil
}
func (s *sshReadScope) Stat(path string) (fs.FileInfo, error) {
	file, err := s.open(path)
	if err != nil {
		return nil, err
	}
	return file.Stat()
}
func (s *sshReadScope) ReadDir(path string, maximum int) ([]fs.DirEntry, error) {
	if maximum < 0 || maximum > 16384 {
		return nil, fmt.Errorf("invalid directory bound")
	}
	file, err := s.open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("expected SSH directory")
	}
	entries, err := file.ReadDir(maximum + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > maximum {
		return nil, fmt.Errorf("directory exceeds bound")
	}
	for _, entry := range entries {
		if strings.ContainsAny(entry.Name(), `/\`) || !windowstarget.ValidateWindowsPath(path+`\`+entry.Name()) {
			return nil, fmt.Errorf("invalid native directory entry")
		}
	}
	return entries, nil
}
func (s *sshReadScope) ReadFile(path string, maximum int) ([]byte, error) {
	image, err := s.image(path, maximum)
	return image.Bytes, err
}
func (s *sshReadScope) pin(path string, directory bool) (SSHPathPin, error) {
	file, err := s.open(path)
	if err != nil {
		return SSHPathPin{}, err
	}
	info, err := file.Stat()
	if err != nil || info.IsDir() != directory {
		return SSHPathPin{}, fmt.Errorf("unexpected SSH path type")
	}
	return file.pin(path)
}
func (s *sshReadScope) identity(path string) (string, error) {
	file, err := s.open(path)
	if err != nil {
		return "", err
	}
	pin, err := file.pin(path)
	return pin.PhysicalID + ":" + string(pin.DescriptorSHA), err
}
func (s *sshReadScope) image(path string, maximum int) (SSHByteImage, error) {
	var image SSHByteImage
	if maximum < 0 || maximum > 64<<20 {
		return image, fmt.Errorf("invalid file bound")
	}
	file, err := s.open(path)
	if err != nil {
		return image, err
	}
	before, err := file.pin(path)
	if err != nil {
		return image, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > int64(maximum) {
		return image, fmt.Errorf("file exceeds bound or is not regular")
	}
	data := make([]byte, info.Size()+1)
	n, err := file.ReadAt(data, 0)
	if err != nil && err != io.EOF {
		return image, err
	}
	after, err := file.pin(path)
	end, endErr := file.Stat()
	if err != nil || endErr != nil || before != after || int64(n) != info.Size() || end.Size() != info.Size() || !end.ModTime().Equal(info.ModTime()) {
		return image, fmt.Errorf("native file changed during read")
	}
	data = data[:n]
	return SSHByteImage{Pin: SSHFilePin{Path: before, Size: int64(n), BytesSHA: digest(data)}, Bytes: data}, nil
}
func (s *sshReadScope) trusted(path, sid string) error {
	if _, err := s.open(path); err != nil {
		return err
	}
	for name, file := range s.held {
		if name == path || strings.HasPrefix(path, name+`\`) || len(name) == 3 && strings.HasPrefix(path, name) {
			mask := uint32(0x000d0040)
			if name == path {
				mask = 0x000d0156
			}
			if err := file.trust(sid, mask); err != nil {
				return err
			}
		}
	}
	return nil
}

var sshVolumeID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func sshPhysicalVolume(path string) bool {
	const prefix = `\\?\Volume{`
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, `}\`) {
		return false
	}
	return sshVolumeID.MatchString(path[len(prefix) : len(path)-2])
}

type sshVolumeBoundary interface {
	capture(string) (string, error)
	fixed(string) bool
	openVolume(string) (sshHeldFile, error)
}

func sshCaptureAnchor(root string, volume sshVolumeBoundary) (sshHeldFile, error) {
	if len(root) != 3 || root[1:] != `:\` || root[0] < 'A' || root[0] > 'Z' && root[0] < 'a' || root[0] > 'z' {
		return nil, fmt.Errorf("invalid Windows drive root")
	}
	physical, err := volume.capture(root)
	if err != nil {
		return nil, err
	}
	if !sshPhysicalVolume(physical) {
		return nil, fmt.Errorf("invalid captured physical volume")
	}
	if !volume.fixed(physical) {
		return nil, fmt.Errorf("SSH requires a fixed physical volume")
	}
	return volume.openVolume(physical)
}
