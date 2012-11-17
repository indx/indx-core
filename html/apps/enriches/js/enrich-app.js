define(['js/utils','text!apps/enriches/round_template.html'], function(u,round) {
	console.log('foo');

	var assert = u.assert, deferred = u.deferred, defined = u.defined;

	var example_round = {
		statement: "M & S Kings X",
		name: { begin: 0, end: 4 },
		location: { begin: 5, end: 15 },
		categories: ['groceries']
	};
	var MatchesView = Backbone.View.extend({
		events: {
			'click .btn' : 'click'
		},
		update:function(results) {
			var this_ = this;
			var button_templ = "<div class='btn' name='<%= text %>'><%= text %></div>";
			this.$el.html(''); // children().remove();
			results.map(function(b) {
				console.log(b);
				this_.$el.append(_(button_templ).template({text:b}));
			});
		},
		click:function(evt) {
			this.trigger('click', $(evt.currentTarget).attr('name'));
		},
		render:function() { return this; }
	});
	var RoundView = Backbone.View.extend({
		template:round,
		tagClass:'round',
		events: {
			'select .select-name' : '_cb_name_input_selection',
			'select .select-location' : '_cb_location_input_sel',
			'click .not-specified' : '_location_not_specified'
		},
		initialize:function(options) {
			assert(options.round, 'please provide a round as an argument');
		},
		_cb_location_input_sel:function(evt) {
			var start = evt.target.selectionStart, end = evt.target.selectionEnd;
			var val = $(evt.target).val().substring(start,end);
			var this_ = this;
			this.$el.find('.display-selected-location').val(val);
			this.$el.find('.input-location').focus();
			this.options.box.ajax('/get_places', 'GET', { q : val })
				.then(function(results) {
					// console.log("PLACE SEARCH  RESULTS ", results);
					this_.loc_matches_view.update(results.entries);
				});			
			// this.loc_matches_view.update([val]);
			this.loc_abbrv = val;
		},
		_cb_name_input_selection:function(evt) {
			var start = evt.target.selectionStart, end = evt.target.selectionEnd;
			var val = $(evt.target).val().substring(start,end);
			var this_ = this;
			this.$el.find('.display-selected-name').val(val);
			this.$el.find('.input-name').focus();
			this.options.box.ajax('/get_establishments', 'GET', { q : val })
				.then(function(results) {
					// console.log("ESTABLISHMENT Q RESULTS ", results);
					this_.name_matches_view.update(results.entries);
				});
			// this.name_matches_view.update([val]);
			this.name_abbrv = val;
		},		
		render:function() {
			var this_ = this;
			var html = _(this.template).template(this.options.round);
			this.$el.html( html );
			var cats = this.$el.find('.categories-input');
			cats.children('.option').remove();
			$.ajax({url:'categories/cat-simple.json', type:"GET", dataType:"json"}).success(function(result) {
				result.categories.map(function(c) {
					var h = _('<option value="<%= text %>"><%= text %></option>').template({text:c});
					cats.append(h);
				});
				$(".chzn-select").chosen({no_results_text: "No results matched"});				
			}).error(function(f) {	console.log("FAIL ", f);});

			this.$el.find('.input-location').typeahead({ source: function(q,process) {
				// put an ajax call to thingy now
				// debug code --
				// var locs = ['london', 'dublin', 'berlin', 'southampton'];
				// process(locs.filter(function(f) { return f.indexOf(q) == 0; }));
				//
				this_.options.box.ajax('/get_places', 'GET', { q: q, startswith: true })
					.then(function(results) { process(results.entries);	});
			}});
			this.$el.find('.input-name').typeahead({ source: function(q,process) {
				// debug code 
				// var locs = ['marks & spencers', 'john lewis', 'harrods'];
				// process(locs.filter(function(f) { return f.indexOf(q) == 0; }));
				this_.options.box.ajax('/get_establishments', 'GET', { q: q, startswith: true })
					.then(function(results) { process(results.entries);	});				
			}});

			this.loc_matches_view = new MatchesView({el:this.$el.find('.match-location')});
			this.loc_matches_view.on('click', function(what) {
				this_.$el.find('.input-location').val(what);
			});
			this.name_matches_view = new MatchesView({el:this.$el.find('.match-name')});
			this.name_matches_view.on('click', function(what) {
				this_.$el.find('.input-name').val(what);
			});
			return this;
		},
		get_values:function() {
			var cats = this.$el.find('.categories-input').val();
			return {
				'place-abbrv': this.loc_abbrv || this.options.round.text,
				'place-full':this.$el.find('.input-location').val(),
				'establishment-abbrv':this.name_abbrv || this.options.round.text,
				'establishment-full':this.$el.find('.input-name').val(),
				'categories': cats
			};
		},
		_location_not_specified:function() {
			this.$el.find('.loc').slideUp();
			this.loc_abbrv = "_NOT_SPECIFIED_";
		},
		hide:function() {
			this.$el.fadeOut('fast');
			this.$el.remove();	
		}
	});
	var EnrichView = Backbone.View.extend({
		events : {
			'click .save' : '_save'
		},
		initialize:function(options) {
			this.options = options;
		},
		show_round:function(round) {
			console.log('showing round >> ', round);
			this.round = round;
			var roundview = new RoundView({round:round, box:this.options.box});
			this.roundview = roundview;
			this.$el.find('.round-holder').children().remove();
			this.$el.find('.round-holder').append(roundview.render().el);
		},
		render:function() {
			$('.save').show();

			return this;
		},
		_save:function() {
			var box = this.options.box;
			var this_ = this;
			var round_vals = this.roundview.get_values();
			console.log("SAVING VALS ", round_vals);
			box.ajax('/save_round', 'POST', { round : round_vals })
				.then(function() {	this_.trigger('save'); 	})
				.fail(function() {	this_.trigger('save'); 	});			
		},
		destroy:function() {
			this.roundview.hide();
		}
	});

	var EnrichApp = Backbone.Model.extend({
		initialize:function(options) {
			var this_ = this;
			this.box = options.box;
			this.persona = options.persona;
			this.view = new EnrichView({el:$('.main')[0], box:options.box});
			$('body').append(this.view.render().el);
			this.next_round();
			this.view.on('save', function() {
				this_.view.destroy();				
				this_.next_round();
			});
			// this.view.show_round(example_round);
		},
		next_round:function() {
			var this_ = this;
			var persona_n = Math.floor(8*Math.random() + 1);
			this.box.ajax('/get_next_round', 'GET', { persona: 'persona' + persona_n }).then(function(x) {
				console.log("LOADING ROUND ", x.round);
				this_.view.show_round(x.round);
			});
		},		
		show:function() {
			this.view.$el.show();
		},
		hide:function() {
			this.view.$el.fadeOut('fast');
			this.view.$el.remove();	
		}				
	});

	return {
		init:function(box) {
			return new EnrichApp({ box: box, persona: 'Persona2' });
		}
	};	
});
