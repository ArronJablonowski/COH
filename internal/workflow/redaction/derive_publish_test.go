package redaction

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func TestDerivationServicePublishesDerivedThenEncryptedMapping(t *testing.T) {
	fixture := newBindingFixture(t)
	state, derivation := publicationFixture(t, fixture)
	calls := []string{}
	transformer := &transformerStub{derivation: derivation, output: bytes.Repeat([]byte("x"), int(derivation.DerivedArtifact.Length)), calls: &calls}
	publisher := &publisherStub{calls: &calls}
	service, err := newDerivationService(transformer, publisher)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.deriveAndPublish(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := []string{"transform", "publish:derived", "publish:mapping"}
	if !equalStrings(calls, wantCalls) {
		t.Fatalf("calls=%v want=%v", calls, wantCalls)
	}
	if result.Derived.Reference.Artifact != derivation.DerivedArtifact ||
		result.Mapping.Reference.Artifact.MediaType != mappingMediaType || result.Mapping.Reference.Artifact.Classification != "restricted" ||
		len(publisher.values) != 2 || contentDigest(publisher.values[1]) != result.Mapping.Reference.Artifact.Digest {
		t.Fatalf("result=%+v values=%d", result, len(publisher.values))
	}
	wantMapping, _ := CanonicalMapping(derivation.Mapping)
	if !bytes.Equal(publisher.values[1], wantMapping) {
		t.Fatal("published mapping was not exact canonical mapping")
	}
	if len(publisher.sources) != 2 || publisher.sources[1] == nil || publisher.sources[1].value != nil {
		t.Fatal("mapping plaintext source was not cleared after publication")
	}
}

func TestDerivationServiceRejectsSubstitutedDerivedPublication(t *testing.T) {
	fixture := newBindingFixture(t)
	state, derivation := publicationFixture(t, fixture)
	calls := []string{}
	transformer := &transformerStub{derivation: derivation, output: bytes.Repeat([]byte("x"), int(derivation.DerivedArtifact.Length)), calls: &calls}
	publisher := &publisherStub{calls: &calls, substitute: true}
	service, _ := newDerivationService(transformer, publisher)
	if _, err := service.deriveAndPublish(context.Background(), state); CodeOf(err) != Denied || len(calls) != 2 {
		t.Fatalf("code=%s err=%v calls=%v", CodeOf(err), err, calls)
	}
}

func TestDerivationServiceClearsPlaintextAndWithholdsOnPublicationFailure(t *testing.T) {
	for _, role := range []PublicationRole{DerivedPublication, MappingPublication} {
		t.Run(string(role), func(t *testing.T) {
			fixture := newBindingFixture(t)
			state, derivation := publicationFixture(t, fixture)
			calls := []string{}
			transformer := &transformerStub{derivation: derivation,
				output: bytes.Repeat([]byte("x"), int(derivation.DerivedArtifact.Length)), calls: &calls}
			publisher := &publisherStub{calls: &calls, failRole: role}
			service, _ := newDerivationService(transformer, publisher)
			if result, err := service.deriveAndPublish(context.Background(), state); err == nil ||
				result.Derived.Reference.Artifact.Digest != "" {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			for _, source := range publisher.sources {
				if source != nil && source.value != nil {
					t.Fatal("publication failure retained plaintext source")
				}
			}
		})
	}
}

func publicationFixture(t *testing.T, fixture bindingFixture) (authorizedState, Derivation) {
	t.Helper()
	mapping := cloneMapping(fixture.mapping)
	mapping.PreviousProvenanceDigest = fixture.command.Source.ManifestProvenanceDigest
	mapping.ProvenanceDigest, mapping.MappingDigest = "", ""
	mapping.ProvenanceDigest, _ = MappingProvenanceDigest(mapping)
	mapping.MappingDigest, _ = MappingBindingDigest(mapping)
	state := authorizedState{Command: fixture.command, IntentDigest: fixture.authorization.IntentDigest,
		Case: fixture.authorizationCase(), Rule: fixture.rule, Plan: fixture.plan, Source: fixture.authorizationSource(),
		Approval: fixture.approval, Authorization: fixture.authorization, Decision: fixture.decision,
		CustodyHead: fixture.command.ExpectedCustodyHead, AuthorizedAt: mapping.CreatedAt}
	request := DerivationRequest{Case: state.Command.Case, Source: state.Command.Source, Verified: state.Source,
		Rule: state.Rule, Plan: state.Plan, CreatedAt: state.AuthorizedAt,
		PreviousProvenanceDigest: state.Command.Source.ManifestProvenanceDigest, Deadline: state.Command.Deadline}
	derivation := Derivation{DerivedArtifact: mapping.DerivedArtifact, Mapping: mapping}
	derivation.DerivationDigest, _ = DerivationBindingDigest(request, derivation)
	return state, derivation
}

type transformerStub struct {
	derivation Derivation
	output     []byte
	calls      *[]string
}

func (stub *transformerStub) Derive(context.Context, DerivationRequest) (Derivation, DerivedSource, error) {
	*stub.calls = append(*stub.calls, "transform")
	return stub.derivation, &sensitiveBytes{value: append([]byte(nil), stub.output...)}, nil
}

type publisherStub struct {
	calls      *[]string
	values     [][]byte
	sources    []*sensitiveBytes
	substitute bool
	failRole   PublicationRole
}

func (stub *publisherStub) Publish(ctx context.Context, request PublicationRequest, source DerivedSource) (PublishedEvidence, error) {
	*stub.calls = append(*stub.calls, "publish:"+string(request.Role))
	buffer := make([]byte, 17)
	value := []byte{}
	owned, _ := source.(*sensitiveBytes)
	stub.sources = append(stub.sources, owned)
	if request.Role == stub.failRole {
		return PublishedEvidence{}, errors.New("publication unavailable")
	}
	for {
		count, err := source.ReadContext(ctx, buffer)
		value = append(value, buffer[:count]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			return PublishedEvidence{}, err
		}
	}
	stub.values = append(stub.values, value)
	artifact := request.ExpectedArtifact
	if stub.substitute {
		artifact.Digest = testDigest("1")
	}
	reference := EvidenceReference{Artifact: artifact,
		Manifest: domain.ArtifactRef{Digest: contentDigest([]byte("manifest:" + string(request.Role))), MediaType: manifestMediaType,
			Classification: artifact.Classification, Length: 512},
		ManifestProvenanceDigest: contentDigest([]byte("provenance:" + string(request.Role))),
		IngestionReceiptDigest:   contentDigest([]byte("receipt:" + string(request.Role)))}
	return PublishedEvidence{Reference: reference, ReceiptDigest: reference.IngestionReceiptDigest}, nil
}
