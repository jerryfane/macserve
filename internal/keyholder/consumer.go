package keyholder

import (
	"context"
	"errors"
	"os"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/worker"
)

// producerRecord is the keyholder's own record of a build-for-testing
// producer whose success receipt it signed: the fields of the producer's
// verified worker seal a consumer's receipt binds, the Xcode it built with,
// and that seal's digest. The controller never supplies any of it.
type producerRecord struct {
	JobID          string      `json:"job_id"`
	SealSHA256     string      `json:"seal_sha256"`
	Repo           string      `json:"repo"`
	SHA            string      `json:"sha"`
	SourceTree     string      `json:"source_tree"`
	RecipeDigest   string      `json:"recipe_digest"`
	Xcode          model.Xcode `json:"xcode"`
	ProductsSHA256 string      `json:"products_sha256"`
	Xctestrun      string      `json:"xctestrun"`
}

// producerRecordName names a producer's record in the release directory;
// Forget removes it with the producer's other records.
func producerRecordName(jobID string) string { return jobID + "-products.json" }

type productsKey struct{}

// ProductsFromContext returns the producer binding of the receipt being
// sealed, nil when it binds none; the keyholder's receipt.Signer Products
// option is this function.
func ProductsFromContext(ctx context.Context, _ model.Job) (*receipt.Products, error) {
	products, _ := ctx.Value(productsKey{}).(*receipt.Products)
	return products, nil
}

// recordProducer records a producer whose success receipt the keyholder
// signed, from its verified seal (bindProducts checked its products, and a
// success seal has the worker's registry resolution). A replay of the same
// seal finds its record; another seal of the same job is refused, so a
// record names exactly one seal.
func (e *Engine) recordProducer(seal buildseal.Seal, sealDigest string) error {
	record := producerRecord{JobID: seal.JobID, SealSHA256: sealDigest, Repo: seal.Request.Repo, SHA: seal.Request.SHA, SourceTree: seal.SourceTree, RecipeDigest: seal.RecipeDigest, Xcode: seal.Resolution.Xcode, ProductsSHA256: seal.ProductsSHA256, Xctestrun: seal.Xctestrun}
	e.mu.Lock()
	defer e.mu.Unlock()
	var prior producerRecord
	err := e.loadRecord(producerRecordName(seal.JobID), &prior)
	if err == nil {
		if prior != record {
			return refusal("producer %s already has a record of another seal", seal.JobID)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return e.saveRecord(producerRecordName(seal.JobID), record)
}

// bindConsumer decides the producer binding of a consumer job's receipt.
// The worker's seal must name the products it verified and imported,
// equal to the request's digest, and the keyholder's own record of the
// producer's signed success must be for the same repository, commit and
// source tree as the tree the worker computed for this job, built with the
// same Xcode, with the same products and .xctestrun: a consumer never binds
// another commit's or recipe's products. A consumer's success receipt
// needs that binding; a consumer that did not succeed gets its failure
// receipt, without a binding when there is none to give. Any other job's
// seal must name no imported products.
func (e *Engine) bindConsumer(job model.Job, seal buildseal.Seal, result worker.Result) (*receipt.Products, error) {
	ref := job.Request.Products
	if ref == nil {
		if seal.ImportedProductsSHA256 != "" {
			return nil, refusal("worker seal names imported test products for a job that consumes none")
		}
		return nil, nil
	}
	products, err := e.producerBinding(job, *ref, seal)
	var refused *RefusalError
	if errors.As(err, &refused) && result.State != model.Succeeded {
		return nil, nil
	}
	return products, err
}

func (e *Engine) producerBinding(job model.Job, ref model.ProductsRef, seal buildseal.Seal) (*receipt.Products, error) {
	if seal.ImportedProductsSHA256 == "" {
		return nil, refusal("a consumer's success receipt needs the test products the worker verified and imported")
	}
	if !profiles.ValidProductsRef(ref) || seal.ImportedProductsSHA256 != ref.SHA256 {
		return nil, refusal("imported test products differ from the request's")
	}
	if !sha40.MatchString(seal.SourceTree) || seal.Source.Commit != job.Request.SHA {
		return nil, refusal("the worker computed no source tree for the consumer's commit")
	}
	var producer producerRecord
	e.mu.Lock()
	err := e.loadRecord(producerRecordName(ref.ProducerJobID), &producer)
	e.mu.Unlock()
	if errors.Is(err, os.ErrNotExist) {
		return nil, refusal("no signed build-for-testing success of producer %s", ref.ProducerJobID)
	}
	if err != nil {
		return nil, err
	}
	switch {
	case producer.JobID != ref.ProducerJobID || !sha256Pattern.MatchString(producer.SealSHA256) || !sha256Pattern.MatchString(producer.RecipeDigest):
		return nil, refusal("producer %s record is invalid", ref.ProducerJobID)
	case producer.Repo != job.Request.Repo || producer.SHA != job.Request.SHA:
		return nil, refusal("producer %s built another repository or commit", ref.ProducerJobID)
	case producer.SourceTree != seal.SourceTree:
		return nil, refusal("producer %s built source tree %s, not the consumer's %s", ref.ProducerJobID, producer.SourceTree, seal.SourceTree)
	case producer.Xcode != job.Request.Xcode:
		return nil, refusal("producer %s built with another Xcode", ref.ProducerJobID)
	case producer.ProductsSHA256 != ref.SHA256 || producer.Xctestrun != ref.Xctestrun:
		return nil, refusal("producer %s sealed other test products", ref.ProducerJobID)
	}
	return &receipt.Products{ProducerJobID: producer.JobID, ProducerSealSHA256: producer.SealSHA256, ProducerRecipeDigest: producer.RecipeDigest, SourceTree: producer.SourceTree, ProductsSHA256: producer.ProductsSHA256, Xctestrun: producer.Xctestrun, SelectorsSource: receipt.SelectorsRepoConfig}, nil
}
